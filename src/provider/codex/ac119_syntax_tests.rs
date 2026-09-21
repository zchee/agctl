//! AC119's syntax layer: every `src/**/*.rs` file parsed with `syn`, and the
//! write-receipt vocabulary DERIVED from what the tree declares (numbered
//! deviation 14).
//!
//! A hand-kept list of the functions that hand out a `WriteReceipt` rotted
//! twice before this file existed: `install` and `remove_named_files` were
//! both missing from it. So nothing here is listed by hand except the seed
//! type itself.
//!
//! - A **carrier** is `WriteReceipt`, or any struct, enum or type alias with
//!   a field (or target) whose type mentions a carrier, to a fixed point.
//!   `CodexWrite` is one because its `Landed` variant holds a receipt.
//! - A **producer** is any function or method, anywhere in the non-test
//!   tree, whose return type mentions a carrier — through `Result`, `Option`,
//!   a tuple, an alias. A helper that returns a receipt is therefore a
//!   producer by its signature, and its callers are checked like any other.
//! - A **consumer** is any function or method with a by-value parameter (or
//!   a by-value `self` of a carrier type) whose type mentions a carrier. Its
//!   own body must audit or return that parameter, like any binding.
//!
//! What a call site resolves to is decided by name, arity and qualifier,
//! never by a list. Rust has no overloading and no default arguments, so a
//! call whose argument count differs from every producer of that name cannot
//! be one; a path call qualified by the owner of a non-producer function of
//! the same name and arity is that function. Anything still ambiguous is
//! treated as a producer (the safe direction: it is checked, and a wrong hit
//! costs an allow row with a reason, never a missed receipt).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use proc_macro2::Span;
use syn::visit::Visit;

use super::Source;

/// The seed of the vocabulary: the type every Codex namespace write returns.
pub(super) const SEED: &str = "WriteReceipt";

/// One parsed source file.
pub(super) struct Parsed {
    pub(super) path: String,
    pub(super) file: syn::File,
}

/// Parses one source file; a file that does not parse is a harness failure,
/// not a finding, so it panics with the file's name.
pub(super) fn parse_one((path, text): &Source) -> Parsed {
    let file = syn::parse_file(text).unwrap_or_else(|err| {
        let at = err.span().start();
        panic!("{path}:{}:{}: does not parse: {err}", at.line, at.column + 1)
    });
    Parsed { path: path.clone(), file }
}

/// Parses every source file, test files included (some rules read them).
pub(super) fn parse(sources: &[Source]) -> Vec<Parsed> {
    sources.iter().map(parse_one).collect()
}

/// The 1-based line a span starts on (`proc-macro2`'s `span-locations`).
pub(super) fn line(span: Span) -> usize {
    span.start().line
}

/// Whether `path` is a unit-test file, which the receipt rule does not read.
pub(super) fn is_test_path(path: &str) -> bool {
    path.ends_with("_tests.rs")
}

/// The module a file defines, by its name: `foo.rs` → `foo`, `mod.rs` → the
/// directory's name.
fn module_of(path: &str) -> String {
    let mut parts = path.trim_end_matches(".rs").rsplit('/');
    match parts.next() {
        Some("mod") => parts.next().unwrap_or_default().to_owned(),
        Some(stem) => stem.to_owned(),
        None => String::new(),
    }
}

/// The last identifier of a type's path, if it is a plain path type.
pub(super) fn type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|seg| seg.ident.to_string()),
        syn::Type::Paren(inner) => type_name(&inner.elem),
        syn::Type::Group(inner) => type_name(&inner.elem),
        _ => None,
    }
}

/// Every identifier a type names by value, anywhere in it
/// (`Result<(A, Option<B>), E>` names `Result`, `A`, `Option`, `B` and `E`).
/// Nothing behind a SHARED `&` counts: `WriteReceipt` is neither `Clone` nor
/// `Copy`, so no owned receipt comes out of one (round 2, A4 (b)). A `&mut`
/// does count: `Option::take` and `mem::replace` move an owned receipt out of
/// it (round 3, A3).
pub(super) fn named_in(ty: &syn::Type) -> BTreeSet<String> {
    struct Names(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Names {
        fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
            self.0.insert(segment.ident.to_string());
            syn::visit::visit_path_segment(self, segment);
        }

        fn visit_type_reference(&mut self, reference: &'ast syn::TypeReference) {
            if reference.mutability.is_some() {
                syn::visit::visit_type_reference(self, reference);
            }
        }
    }
    let mut names = Names(BTreeSet::new());
    names.visit_type(ty);
    names.0
}

/// A struct, an enum or a type alias, as the vocabulary needs it.
pub(super) enum TypeDef<'a> {
    Struct(&'a syn::Fields),
    Enum(Vec<(String, &'a syn::Fields)>),
    Alias(&'a syn::Type),
}

/// One function or method definition.
pub(super) struct FnDef<'a> {
    /// The file it is defined in.
    pub(super) file: &'a str,
    /// The `impl`'s self type, the trait's name, or the module's name.
    pub(super) owner: String,
    pub(super) sig: &'a syn::Signature,
    pub(super) body: Option<&'a syn::Block>,
}

impl FnDef<'_> {
    pub(super) fn name(&self) -> String {
        self.sig.ident.to_string()
    }

    /// Whether the first input is a `self` receiver.
    pub(super) fn has_receiver(&self) -> bool {
        matches!(self.sig.inputs.first(), Some(syn::FnArg::Receiver(_)))
    }

    /// The argument count a method-call spelling passes.
    pub(super) fn method_arity(&self) -> Option<usize> {
        self.has_receiver().then(|| self.sig.inputs.len().saturating_sub(1))
    }

    /// The argument count a path-call spelling passes (UFCS counts `self`).
    pub(super) fn path_arity(&self) -> usize {
        self.sig.inputs.len()
    }
}

/// Collects every type and function definition of one file.
struct Collector<'a> {
    file: &'a str,
    module: Vec<String>,
    owner: Option<String>,
    types: Vec<(String, TypeDef<'a>)>,
    fns: Vec<FnDef<'a>>,
    renames: Vec<(String, String)>,
}

impl<'a> Collector<'a> {
    fn current_owner(&self) -> String {
        self.owner.clone().or_else(|| self.module.last().cloned()).unwrap_or_default()
    }
}

impl<'a> Visit<'a> for Collector<'a> {
    fn visit_item_mod(&mut self, item: &'a syn::ItemMod) {
        self.module.push(item.ident.to_string());
        syn::visit::visit_item_mod(self, item);
        self.module.pop();
    }

    fn visit_item_struct(&mut self, item: &'a syn::ItemStruct) {
        self.types.push((item.ident.to_string(), TypeDef::Struct(&item.fields)));
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'a syn::ItemEnum) {
        let variants =
            item.variants.iter().map(|variant| (variant.ident.to_string(), &variant.fields));
        self.types.push((item.ident.to_string(), TypeDef::Enum(variants.collect())));
        syn::visit::visit_item_enum(self, item);
    }

    fn visit_use_rename(&mut self, rename: &'a syn::UseRename) {
        self.renames.push((rename.ident.to_string(), rename.rename.to_string()));
        syn::visit::visit_use_rename(self, rename);
    }

    fn visit_item_type(&mut self, item: &'a syn::ItemType) {
        self.types.push((item.ident.to_string(), TypeDef::Alias(&item.ty)));
        syn::visit::visit_item_type(self, item);
    }

    fn visit_item_fn(&mut self, item: &'a syn::ItemFn) {
        // A free function belongs to its module even inside an `impl` body's
        // nested item: `owner` is only an `impl`/`trait` context.
        let saved = self.owner.take();
        self.fns.push(FnDef {
            file: self.file,
            owner: self.current_owner(),
            sig: &item.sig,
            body: Some(&item.block),
        });
        syn::visit::visit_item_fn(self, item);
        self.owner = saved;
    }

    fn visit_item_impl(&mut self, item: &'a syn::ItemImpl) {
        let saved = self.owner.replace(type_name(&item.self_ty).unwrap_or_default());
        syn::visit::visit_item_impl(self, item);
        self.owner = saved;
    }

    fn visit_impl_item_fn(&mut self, item: &'a syn::ImplItemFn) {
        self.fns.push(FnDef {
            file: self.file,
            owner: self.current_owner(),
            sig: &item.sig,
            body: Some(&item.block),
        });
        let saved = self.owner.take();
        syn::visit::visit_impl_item_fn(self, item);
        self.owner = saved;
    }

    fn visit_item_trait(&mut self, item: &'a syn::ItemTrait) {
        let saved = self.owner.replace(item.ident.to_string());
        syn::visit::visit_item_trait(self, item);
        self.owner = saved;
    }

    fn visit_trait_item_fn(&mut self, item: &'a syn::TraitItemFn) {
        self.fns.push(FnDef {
            file: self.file,
            owner: self.current_owner(),
            sig: &item.sig,
            body: item.default.as_ref(),
        });
        let saved = self.owner.take();
        syn::visit::visit_trait_item_fn(self, item);
        self.owner = saved;
    }
}

/// The derived receipt vocabulary of a tree.
pub(super) struct Vocabulary<'a> {
    /// `WriteReceipt` and every type that can hold one.
    pub(super) carriers: BTreeSet<String>,
    /// Every struct, enum and alias of the non-test tree, by name. A name
    /// defined twice keeps both definitions.
    pub(super) types: BTreeMap<String, Vec<TypeDef<'a>>>,
    /// Every function and method of the non-test tree.
    pub(super) fns: Vec<FnDef<'a>>,
    /// `fns` indices by name, so a call site resolves without a full scan.
    by_name: BTreeMap<String, Vec<usize>>,
    /// Per `fns` index: whether it is a producer.
    producer: Vec<bool>,
    /// Per `fns` index: its by-value receipt parameters.
    params: Vec<Vec<(String, syn::Type)>>,
}

impl<'a> Vocabulary<'a> {
    /// Derives the vocabulary from the non-test files of `parsed`.
    pub(super) fn derive(parsed: &[&'a Parsed]) -> Self {
        let mut types: BTreeMap<String, Vec<TypeDef<'a>>> = BTreeMap::new();
        let mut fns = Vec::new();
        let mut renames: Vec<(String, String)> = Vec::new();
        for file in parsed.iter().filter(|file| !is_test_path(&file.path)) {
            let mut collector = Collector {
                file: &file.path,
                module: vec![module_of(&file.path)],
                owner: None,
                types: Vec::new(),
                fns: Vec::new(),
                renames: Vec::new(),
            };
            collector.visit_file(&file.file);
            for (name, def) in collector.types {
                types.entry(name).or_default().push(def);
            }
            fns.extend(collector.fns);
            renames.extend(collector.renames);
        }

        let mut carriers = BTreeSet::from([SEED.to_owned()]);
        loop {
            let before = carriers.len();
            for (name, defs) in &types {
                if carriers.contains(name) {
                    continue;
                }
                let holds = defs.iter().any(|def| match def {
                    TypeDef::Struct(fields) => fields_hold(fields, &carriers),
                    TypeDef::Enum(variants) => {
                        variants.iter().any(|(_, fields)| fields_hold(fields, &carriers))
                    }
                    TypeDef::Alias(ty) => mentions(ty, &carriers, None),
                });
                if holds {
                    carriers.insert(name.clone());
                }
            }
            // `use …::WriteReceipt as X`: the rename names a carrier too
            // (round 2, A8), keyed by name like everything here.
            for (original, rename) in &renames {
                if carriers.contains(original) {
                    carriers.insert(rename.clone());
                }
            }
            if carriers.len() == before {
                break;
            }
        }
        let mut vocab = Self {
            carriers,
            types,
            fns,
            by_name: BTreeMap::new(),
            producer: Vec::new(),
            params: Vec::new(),
        };
        for (index, def) in vocab.fns.iter().enumerate() {
            vocab.by_name.entry(def.name()).or_default().push(index);
        }
        vocab.producer = vocab.fns.iter().map(|def| vocab.returns_carrier(def)).collect();
        vocab.params = vocab.fns.iter().map(|def| vocab.carrier_params(def)).collect();
        vocab
    }

    /// The definitions named `name`, with their index.
    fn named(&self, name: &str) -> impl Iterator<Item = (usize, &FnDef<'a>)> {
        self.by_name.get(name).into_iter().flatten().map(|&index| (index, &self.fns[index]))
    }

    /// Whether `ty` (read inside an `impl` of `owner`, for `Self`) can hold
    /// a receipt.
    pub(super) fn carries(&self, ty: &syn::Type, owner: Option<&str>) -> bool {
        mentions(ty, &self.carriers, owner)
    }

    /// Whether `def` hands out a receipt: its return type mentions a carrier.
    pub(super) fn is_producer(&self, def: &FnDef<'_>) -> bool {
        self.index_of(def).map_or_else(|| self.returns_carrier(def), |index| self.producer[index])
    }

    fn index_of(&self, def: &FnDef<'_>) -> Option<usize> {
        self.named(&def.name()).find(|(_, other)| std::ptr::eq(other.sig, def.sig)).map(|(i, _)| i)
    }

    fn returns_carrier(&self, def: &FnDef<'_>) -> bool {
        match &def.sig.output {
            syn::ReturnType::Type(_, ty) => self.carries(ty, Some(&def.owner)),
            syn::ReturnType::Default => false,
        }
    }

    /// The by-value parameters of `def` that can hold a receipt, by name
    /// (`self` for a by-value receiver on a carrier type).
    pub(super) fn receipt_params(&self, def: &FnDef<'_>) -> Vec<(String, syn::Type)> {
        match self.index_of(def) {
            Some(index) => self.params[index].clone(),
            None => self.carrier_params(def),
        }
    }

    fn carrier_params(&self, def: &FnDef<'_>) -> Vec<(String, syn::Type)> {
        let mut params = Vec::new();
        for input in &def.sig.inputs {
            match input {
                syn::FnArg::Receiver(receiver) => {
                    if matches!(receiver.kind, syn::ReceiverKind::Value)
                        && self.carriers.contains(&def.owner)
                    {
                        params.push(("self".to_owned(), owner_type(&def.owner)));
                    }
                }
                syn::FnArg::Typed(typed) => {
                    if matches!(*typed.ty, syn::Type::Reference(_)) {
                        continue;
                    }
                    if self.carries(&typed.ty, Some(&def.owner))
                        && let syn::Pat::Ident(ident) = &*typed.pat
                    {
                        params.push((ident.ident.to_string(), (*typed.ty).clone()));
                    }
                }
            }
        }
        params
    }

    /// The producers a method call `.name(args)` may resolve to.
    pub(super) fn method_producers(&self, name: &str, argc: usize) -> Vec<&FnDef<'a>> {
        self.named(name)
            .filter(|(index, def)| def.method_arity() == Some(argc) && self.producer[*index])
            .map(|(_, def)| def)
            .collect()
    }

    /// The producers a path call `q::name(args)` may resolve to. A qualifier
    /// that names the owner of a NON-producer definition with the same name
    /// and arity resolves the call to that definition.
    pub(super) fn path_producers(&self, path: &syn::Path, argc: usize) -> Vec<&FnDef<'a>> {
        let Some(name) = path.segments.last().map(|seg| seg.ident.to_string()) else {
            return Vec::new();
        };
        let qualifier = qualifier(path);
        let same: Vec<(usize, &FnDef<'a>)> =
            self.named(&name).filter(|(_, def)| def.path_arity() == argc).collect();
        if let Some(qualifier) = &qualifier
            && qualifier != "Self"
            && same.iter().any(|(index, def)| !self.producer[*index] && def.owner == *qualifier)
        {
            return Vec::new();
        }
        same.into_iter().filter(|(index, _)| self.producer[*index]).map(|(_, def)| def).collect()
    }

    /// Whether a method call `.name(args)` resolves ONLY to consumers that
    /// take argument `index` as a receipt (`None` = the receiver). A name that
    /// could also be a non-consumer is not a consumer (the safe direction:
    /// the receipt stays unaccounted for).
    pub(super) fn method_consumes(&self, name: &str, argc: usize, index: Option<usize>) -> bool {
        let defs: Vec<_> =
            self.named(name).filter(|(_, def)| def.method_arity() == Some(argc)).collect();
        !defs.is_empty()
            && defs.iter().all(|(slot, def)| {
                let wanted = match index {
                    None => "self".to_owned(),
                    Some(index) => param_name(def, index + 1),
                };
                self.params[*slot].iter().any(|(param, _)| *param == wanted)
            })
    }

    /// As [`Self::method_consumes`], for a path call's argument `index`.
    pub(super) fn path_consumes(&self, path: &syn::Path, argc: usize, index: usize) -> bool {
        let Some(name) = path.segments.last().map(|seg| seg.ident.to_string()) else {
            return false;
        };
        let defs: Vec<_> = self.named(&name).filter(|(_, def)| def.path_arity() == argc).collect();
        !defs.is_empty()
            && defs.iter().all(|(slot, def)| {
                let wanted = param_name(def, index);
                self.params[*slot].iter().any(|(param, _)| *param == wanted)
            })
    }

    /// The struct fields, or one enum variant's fields, a pattern or a
    /// literal names: `WriteReceipt`, `CodexWrite::Landed`, `Self`.
    pub(super) fn fields_named(&self, path: &syn::Path, owner: &str) -> Vec<&'a syn::Fields> {
        let idents: Vec<String> = path.segments.iter().map(|seg| seg.ident.to_string()).collect();
        let resolve = |name: &str| if name == "Self" { owner.to_owned() } else { name.to_owned() };
        let mut found = Vec::new();
        if let Some(last) = idents.last() {
            for def in self.types.get(&resolve(last)).into_iter().flatten() {
                if let TypeDef::Struct(fields) = def {
                    found.push(*fields);
                }
            }
        }
        if idents.len() >= 2 {
            let enum_name = resolve(&idents[idents.len() - 2]);
            let variant = &idents[idents.len() - 1];
            for def in self.types.get(&enum_name).into_iter().flatten() {
                if let TypeDef::Enum(variants) = def {
                    found.extend(
                        variants.iter().filter(|(name, _)| name == variant).map(|(_, f)| *f),
                    );
                }
            }
        }
        found
    }

    /// The type a pattern or literal path names, when it names a carrier or
    /// a known type (`CodexWrite::Landed` → `CodexWrite`).
    pub(super) fn type_of_path(&self, path: &syn::Path, owner: &str) -> Option<String> {
        let idents: Vec<String> = path.segments.iter().map(|seg| seg.ident.to_string()).collect();
        let resolve = |name: &str| if name == "Self" { owner.to_owned() } else { name.to_owned() };
        let last = resolve(idents.last()?);
        if self
            .types
            .get(&last)
            .is_some_and(|defs| defs.iter().any(|d| matches!(d, TypeDef::Struct(_))))
        {
            return Some(last);
        }
        let enum_name = resolve(idents.get(idents.len().checked_sub(2)?)?);
        self.types.contains_key(&enum_name).then_some(enum_name)
    }
}

/// The `index`-th input's binding name (`self` for a receiver).
fn param_name(def: &FnDef<'_>, index: usize) -> String {
    match def.sig.inputs.iter().nth(index) {
        Some(syn::FnArg::Receiver(_)) => "self".to_owned(),
        Some(syn::FnArg::Typed(typed)) => match &*typed.pat {
            syn::Pat::Ident(ident) => ident.ident.to_string(),
            _ => String::new(),
        },
        None => String::new(),
    }
}

/// The segment before a path's last one (`audit` in `audit::append`).
pub(super) fn qualifier(path: &syn::Path) -> Option<String> {
    let len = path.segments.len();
    (len >= 2).then(|| path.segments[len - 2].ident.to_string())
}

/// A plain path type naming `owner`.
pub(super) fn owner_type(owner: &str) -> syn::Type {
    syn::parse_str(owner).unwrap_or_else(|_| syn::parse_str("()").expect("unit parses"))
}

fn fields_hold(fields: &syn::Fields, carriers: &BTreeSet<String>) -> bool {
    fields.iter().any(|field| mentions(&field.ty, carriers, None))
}

/// Whether `ty` names a carrier (`Self` read as `owner`).
fn mentions(ty: &syn::Type, carriers: &BTreeSet<String>, owner: Option<&str>) -> bool {
    named_in(ty).iter().any(|name| {
        carriers.contains(name) || (name == "Self" && owner.is_some_and(|o| carriers.contains(o)))
    })
}

/// The vocabulary of one synthetic file, for tests of the derivation itself
/// that must not depend on the real tree's names.
#[test]
fn the_carrier_closure_is_a_fixed_point_not_a_pass_count() {
    // A depth-4 chain declared in REVERSE sort order: `Aa` holds `Ab` holds
    // `Ac` holds `Ad` holds a receipt. Carriers are visited in name order,
    // so each level is found one pass after the one it holds: any fixed
    // number of passes below four misses `Aa` (round 2, A3).
    let source = (
        "src/synthetic.rs".to_owned(),
        "struct Aa { b: Ab }\n\
         struct Ab { c: Ac }\n\
         struct Ac { d: Ad }\n\
         struct Ad { r: WriteReceipt }\n\
         struct Ca { b: Option<Box<Cb>> }\n\
         struct Cb { a: Option<Box<Ca>>, r: WriteReceipt }\n\
         struct Na { b: Box<Nb> }\n\
         struct Nb { a: Box<Na> }\n\
         struct Borrowing<'r> { r: &'r WriteReceipt }\n\
         use self::Renamed as Renamed2;\n\
         use crate::provider::codex::auth_store::WriteReceipt as Renamed;\n\
         struct Zz { r: Renamed }\n\
         struct Holder;\n\
         impl Holder {\n\
             fn peek(&self) -> &WriteReceipt { todo!() }\n\
             fn take(self) -> Option<Renamed> { todo!() }\n\
         }\n"
        .to_owned(),
    );
    let parsed = parse_one(&source);
    let vocab = Vocabulary::derive(&[&parsed]);
    // `Renamed2` renames `Renamed` and is declared BEFORE it: the rename
    // table is closed inside the same fixed point, not in one pass after.
    for carrier in ["Aa", "Ab", "Ac", "Ad", "Ca", "Cb", "Renamed", "Renamed2", "Zz"] {
        assert!(
            vocab.carriers.contains(carrier),
            "`{carrier}` is not a carrier: {:?}",
            vocab.carriers
        );
    }
    // A cycle with no receipt terminates and carries nothing; a struct that
    // only BORROWS a receipt owes no audit.
    for plain in ["Na", "Nb", "Borrowing", "Holder"] {
        assert!(!vocab.carriers.contains(plain), "`{plain}` is a carrier: {:?}", vocab.carriers);
    }
    let producer = |name: &str| {
        vocab.fns.iter().filter(|def| def.name() == name).any(|def| vocab.is_producer(def))
    };
    assert!(!producer("peek"), "a `&WriteReceipt` getter is not a producer");
    assert!(producer("take"), "a renamed receipt in the return type is a producer");
}
