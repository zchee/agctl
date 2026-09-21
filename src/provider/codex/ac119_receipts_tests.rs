//! AC119 (A): every write receipt reaches `codex::audit::append`, per
//! BINDING, not per file (bead `agctl-meqv`).
//!
//! The rule this replaces was "a file that takes receipts calls
//! `audit::append` somewhere", which a second, unaudited receipt in an
//! audited file passes. This one follows each receipt by name through the
//! function that holds it, using the vocabulary `ac119_syntax_tests.rs`
//! derives from the tree's signatures:
//!
//! - **R6c — every binding is accounted for.** A `let`, a `match` arm, an
//!   `if let`/`while let` or a parameter that binds a value able to hold a
//!   receipt must, later in its own scope, hand it to `audit::append`, to a
//!   derived consumer, or out of the function (a tail, a `return`, a new
//!   binding that is itself checked). A pattern that drops a receipt — `_`,
//!   an `_name`, a `..` that skips a receipt field — is a violation where it
//!   stands. Which positions of a pattern hold a receipt is read from the
//!   producer's return type and the struct and enum definitions, so
//!   `let (decision, receipt, _evidence) = ns.resolve_pending(..)?` tracks
//!   `receipt` alone.
//! - **R6d — no receipt is used where nothing follows it.** A producer call
//!   (or a receipt literal) as the receiver of a non-adapter method, an
//!   argument of a non-consumer, an operand, an assignment's right side:
//!   `drop(ns.install(f)?)`, `ns.write(..).is_ok()`; and a statement whose
//!   value carries a receipt, which drops it where it stands:
//!   `ns.resolve_pending(c)?;`, `r.take();` on a `&mut` parameter.
//! - **R6e — the early exit.** Between a receipt's binding and the statement
//!   that accounts for it, no `?`, `return`, `break` or `continue` at that
//!   depth: `let r = install(..)?; step()?; audit::append(p, r)?;` drops `r`
//!   when `step` fails. It runs in every scope a receipt is bound in — a
//!   statement list, a `match` arm, an `if let`/`while let` body — and
//!   inside the auditing call itself: a `?` in any OTHER argument (or the
//!   receiver) of the call that takes the receipt drops it too
//!   (`audit::append(paths()?, receipt)?`). Three more places:
//!   - the HEAD of the statement that accounts for the receipt — an
//!     `if`/`while` condition (every operand of a `&&` chain, also either
//!     side of a `let` that moves the receipt in) or a `match` scrutinee:
//!     `if review_ok()? { audit::append(p, r)?; }`. Evaluation order counts:
//!     the scan stops at the call that takes the receipt, whose arguments
//!     and receiver are the audit call's (above), and what runs after that
//!     call runs after the audit (`if audit::append(p, r).is_ok() && x()?`).
//!     A call reached on one branch of an `if`/`match`, right of `&&`/`||`
//!     or in a loop body may not run, so the scan goes on past it
//!     (`if (c || audit::append(p, r).is_ok()) && x()?` reports `x()?`);
//!   - a let CHAIN after a `let` that PRODUCES the receipt:
//!     `if let Ok((r, _)) = i.install(f) && x()? { … }` (left of that `let`
//!     no receipt exists yet, so an exit there drops nothing). A `let` that
//!     only moves a live receipt in is the head's; one that does both
//!     (`if let (Some(a), Ok((b, _))) = (Some(r), i.install(f)) && x()?`)
//!     has its exit reported by both faces, once per receipt;
//!   - the BODY that holds the use, entered from that statement — the then
//!     or `else` branch, an `else if` (its head too), a `match` arm block, a
//!     `while`/`loop` body, a bare block, the initializer of a `let` — and
//!     scanned as a statement list of its own, as deep as the use sits:
//!     `if c { step()?; audit::append(p, r)?; }`. A head that hands the
//!     receipt on (`if let Some(r2) = r`, `match r { … }`) ends the descent:
//!     the new binding is checked on its own. In a descended loop body a
//!     `break` before the use is an exit (it leaves with the receipt
//!     unaudited), and so is a `continue` (fail-safe).
//! - **R6f — no stale allow row.** An exception names a file, a function and
//!   a binding, carries its reason, and fails when it matches nothing.
//!
//! The statement-position drop is R6d's for every carrier, `ns.install(f)?;`
//! included, although `#[must_use]` on `WriteReceipt` and `CodexWrite` also
//! warns there: which types that lint looks through (a tuple yes, an
//! `Option` no) is a toolchain detail the rule must not depend on.
//!
//! A field of a binding handed to the auditing call counts as a use of the
//! binding (`audit::append(p, got.receipt)`). A `&WriteReceipt` is not a
//! receipt: a SHARED borrow owes nothing, because `WriteReceipt` is neither
//! `Clone` nor `Copy` and nothing owned comes out of `&`. A fn that RETURNS
//! `&mut` to a carrier stays a producer (`Option::take` and `mem::replace`
//! move an owned receipt out of it). A `ref`/`ref mut` binding of a receipt
//! is a drop ("binds it by reference … (bind it by value)").
//!
//! **Unsupported shape: a collection of receipts.** A `for` over a binding
//! that holds receipts is not a use of it — the binding is reported (R6c),
//! and a producer's result iterated directly is R6d. Every producer today
//! returns ONE receipt and audits it where it is produced; audit each one
//! there, or add an `ALLOW` row with a reason.
//!
//! **Residuals, stated rather than hidden.**
//! - The `Group` arm of `flows`, `carried` and `produces_in` is UNPINNED.
//!   syn builds `Expr::Group` only around an expression a macro captured, so
//!   `syn::parse_file` of source text never yields one, and a parsed tree is
//!   the only entry the tests have (`violations` takes a `Vocabulary` built
//!   from one). The arms are kept all the same, so that no kind [`flows`]
//!   looks through reaches `produces_in`'s catch-all — dropping the arm
//!   would restore on paper the asymmetry this rule removes.
//! - A struct literal that names a field BESIDE a functional-update operand
//!   (`Pair { n: 1, ..w }`): struct-update moves from the base only the
//!   fields the literal does not name, and the analyser cannot tell `n: 1`
//!   from `r: None`, so the operand is NOT followed. Rust DOES move `w.r`
//!   there — the literal names `n`, not `r` — so "the base stays live" is
//!   the ANALYSER's conservative reading of a base it cannot resolve, not a
//!   claim about Rust; its cost is an over-report, never a silent drop. The
//!   exit right of such a `let` is reported by the CHAIN face and `w` is
//!   reported by R6c — 2 findings, where the head face alone would be ideal,
//!   and this is the one written exception to "the chain owns what a `let`
//!   PRODUCES": nothing is produced here. Both findings are PINNED, each by
//!   its own row: the CHAIN face by `the residual: a named field beside a
//!   struct-update operand keeps the base live` in
//!   [`every_r6e_exit_is_reported_once_by_its_own_face`], and the R6c by the
//!   plant `a struct update beside a named field is not an audit of its
//!   base`. Following the operand would make
//!   `audit::append(p, Pair { r: None, ..w })` read as an audit of `w`,
//!   which is a SILENT drop; removing the guard turns both rows red. A pure
//!   re-wrap (`Wrap { ..w }`, no named field) IS followed and is the head's.
//! - Flow-insensitive within a scope: a receipt audited on one branch only
//!   (`if c { audit::append(p, r)?; }`) passes, and so does one whose other
//!   branch LEAVES without it (`if c { audit::append(p, r)?; } else {
//!   return Err(e); }`): a branch that does not use the receipt is not
//!   scanned. So does a receipt that flows into a block tail whose value is
//!   then discarded.
//! - A carrier holding TWO receipts, one handed to the audit by field: the
//!   field use counts for the whole binding, so the other is not followed.
//! - An early exit in the auditing statement outside a head, a descended
//!   body and the audit call's own arguments — in a method chain around the
//!   call (`x()?.then(audit::append(p, r))`), in an argument's block
//!   (`f({ step()?; audit::append(p, r)? })`), in an `if`/`match` that is an
//!   operand or an argument rather than the statement itself, in the
//!   guard of an arm that uses an enclosing receipt
//!   (`match k { _ if step()? => audit::append(p, r)?, _ => … }`), in a
//!   `for` iterator expression or a `for` body
//!   (`for n in list()? { audit::append(p, r)?; break; }`), or in an `async`
//!   block the receipt is moved into (`async move { x()?; audit::append(p,
//!   r) }`): not scanned. The descent enters only the shapes named under
//!   R6e.
//! - Renames are keyed by name: `use …::WriteReceipt as X` is followed; a
//!   rename of a PRODUCER function (`use …::install as i`) is not — the
//!   producer set is keyed by the defined name.
//! - An early exit inside a CLOSURE that has captured the receipt
//!   (`(|| { if c { return; } audit::append(p, receipt) })()`): `EarlyExit`
//!   does not enter closures, by design (their exits leave the closure).
//! - Moving a receipt out of a `&mut` carrier FIELD with no getter
//!   (`h.slot.take()` on `h: &mut Holder`) is not followed; a getter that
//!   returns `&mut` to a carrier is (it stays a producer). A `&mut`
//!   PARAMETER is followed where it is named: `r.take()`, `r.replace(x)`,
//!   `r.take_if(f)`, and `take(r)` / `replace(r, x)` under any path
//!   (`std::mem::`, `Option::`, an import), `r` also spelled `&mut *r`,
//!   yield an owned receipt, checked like any binding
//!   (`fn f(r: &mut Option<WriteReceipt>) { let x = r.take(); drop(x); }` is
//!   R6c). Not followed: a reborrow alias (`let s = &mut *r; let x =
//!   s.take();`), `std::mem::swap(r, &mut other)`, and an assignment through
//!   the parameter (`*r = None;`), which drops the receipt it held with no
//!   binding to report.
//! - What is moved out of a `&mut` parameter and used where nothing follows
//!   it without a binding or a statement of its own: `drop(r.take());`,
//!   `_ = r.take();`. R6d asks those positions for a PRODUCER, and `take`
//!   on a parameter is not one (a statement `r.take();` is reported).
//! - Names, not places: a later `let receipt = other;` that shadows a
//!   receipt and is then audited satisfies the first binding.
//! - Macro token streams are opaque: a producer or a receipt inside
//!   `format!`, `tracing::warn!` or any macro is not seen, as a use or as a
//!   drop.
//! - A closure that returns a receipt counts as handing it out, whether or
//!   not the closure is ever called.
//! - One function at a time: a receipt passed to a consumer is judged by the
//!   consumer's own body, and a call is resolved by name, arity and
//!   qualifier. A name that is ambiguous resolves to "producer" (checked) and
//!   to "not a consumer" (still owed) — both the safe direction.
//! - A labelled `break`/`continue` that leaves an outer loop from inside an
//!   inner one is not counted as an early exit.

use proc_macro2::Span;
use syn::visit::Visit;

use super::syntax::FnDef;
use super::syntax::Vocabulary;
use super::syntax::line;
use super::syntax::owner_type;
use super::syntax::qualifier;

/// The one terminal consumer: `codex::audit::append(paths, receipt)`. It is
/// matched by its qualified spelling; passing a receipt BY VALUE is what
/// makes it this function — `secret::audit::append` takes `&AuditEntry`.
const SINK_FILE: &str = "src/provider/codex/audit.rs";
const SINK_FN: &str = "append";

/// Methods that hand their receiver's value on (`Result`/`Option` adapters).
const ADAPTERS: [&str; 7] =
    ["map_err", "inspect_err", "inspect", "ok", "expect", "unwrap", "unwrap_or_else"];

/// How to satisfy R6c and R6e, appended to every such finding.
const COMPLY: &str = " — to comply, pass the binding itself to `audit::append`, return it, or hand it to a \
     fn that takes a `WriteReceipt`, with no `?`/`return`/`break`/`continue` before (a collection of \
     receipts is not supported: audit each one where it is produced); or add an `ALLOW` row with a \
     reason";

/// How to satisfy R6d, appended to every such finding.
const COMPLY_LOST: &str = " — to comply, bind the result with `let` and pass the binding to \
     `audit::append`, to a fn that takes a `WriteReceipt`, or to the caller; or add an `ALLOW` row \
     with a reason";

/// An exception: file, enclosing function, binding, and why.
pub(super) type Allow = (&'static str, &'static str, &'static str, &'static str);

/// Today's exceptions: none. Every row must match a finding (R6f).
pub(super) const ALLOW: &[Allow] = &[];

/// One violation, before the allow rows are applied.
struct Finding {
    rule: &'static str,
    file: String,
    line: usize,
    func: String,
    binding: String,
    message: String,
}

/// Every R6c–R6f violation in the non-test files of the vocabulary's tree.
pub(super) fn violations(vocab: &Vocabulary<'_>, allow: &[Allow]) -> Vec<String> {
    let (findings, _) = run(vocab);
    let mut used = vec![false; allow.len()];
    let mut out = Vec::new();
    for finding in findings {
        let row = allow.iter().position(|(file, func, binding, _)| {
            *file == finding.file && *func == finding.func && *binding == finding.binding
        });
        match row {
            Some(index) => used[index] = true,
            None => out.push(format!(
                "{}: {}:{}: in `{}`, {}",
                finding.rule, finding.file, finding.line, finding.func, finding.message
            )),
        }
    }
    for (file, func, binding, reason) in allow {
        if reason.trim().is_empty() {
            out.push(format!(
                "R6f: {file}: the allow row for `{binding}` in `{func}` has no reason; a row must say why"
            ));
        }
    }
    for ((file, func, binding, reason), used) in allow.iter().zip(used) {
        if !used {
            out.push(format!(
                "R6f: {file}: the allow row for `{binding}` in `{func}` ({reason}) matches nothing"
            ));
        }
    }
    out
}

/// The rule's census on a tree, each entry `file:fn:name`.
pub(super) struct Census {
    /// Every receipt binding the rule visited.
    pub(super) followed: Vec<String>,
    /// Every binding the early-exit clause (R6e) actually RAN on — the
    /// round-1 census counted visits only, and four real sites were visited
    /// but never checked.
    pub(super) exit_checked: Vec<String>,
}

/// The census — the positive control that the rule is not vacuous on the
/// real tree.
pub(super) fn census(vocab: &Vocabulary<'_>) -> Census {
    let (_, census) = run(vocab);
    census
}

fn run(vocab: &Vocabulary<'_>) -> (Vec<Finding>, Census) {
    let mut findings = Vec::new();
    let mut census = Census { followed: Vec::new(), exit_checked: Vec::new() };
    for def in vocab.fns.iter().filter(|def| def.body.is_some()) {
        let mut checker = Checker {
            vocab,
            def,
            findings: Vec::new(),
            followed: Vec::new(),
            exit_checked: Vec::new(),
            mut_params: Vec::new(),
        };
        checker.check_fn();
        findings.extend(checker.findings);
        census.followed.extend(checker.followed);
        census.exit_checked.extend(checker.exit_checked);
    }
    (findings, census)
}

/// A value's type as far as the rule can tell.
#[derive(Clone)]
enum Ty {
    /// A written type, read inside `owner` (for `Self`).
    Known(Box<syn::Type>, String),
    /// Not known; whether the enclosing position can hold a receipt.
    Unknown(bool),
}

/// A written type, read inside `owner`.
fn known(ty: syn::Type, owner: String) -> Ty {
    Ty::Known(Box::new(ty), owner)
}

/// A name a pattern binds.
struct Bound {
    name: String,
    span: Span,
    ty: Ty,
    carrying: bool,
}

/// What a pattern binds and what it drops.
#[derive(Default)]
struct Aligned {
    bound: Vec<Bound>,
    drops: Vec<(Span, String)>,
}

/// The names in scope that can hold a receipt (`None` = shadowed by a name
/// that cannot).
type Env = Vec<(String, Option<Ty>)>;

/// Whether a value in this position goes somewhere the rule follows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Kept,
    Lost,
}

/// Where a binding must be accounted for.
enum Scope<'s> {
    Stmts(&'s [syn::Stmt]),
    Expr(&'s syn::Expr),
}

struct Checker<'v, 'a> {
    vocab: &'v Vocabulary<'a>,
    def: &'v FnDef<'a>,
    findings: Vec<Finding>,
    followed: Vec<String>,
    exit_checked: Vec<String>,
    /// The `&mut` parameters that can hold a receipt, with the type behind
    /// the reference: they owe nothing, what is moved out of them does.
    mut_params: Vec<(String, syn::Type)>,
}

impl Checker<'_, '_> {
    fn owner(&self) -> &str {
        &self.def.owner
    }

    fn push(&mut self, rule: &'static str, line: usize, binding: &str, message: String) {
        self.findings.push(Finding {
            rule,
            file: self.def.file.to_owned(),
            line,
            func: self.def.name(),
            binding: binding.to_owned(),
            message,
        });
    }

    fn check_fn(&mut self) {
        let Some(body) = self.def.body else { return };
        let is_sink = self.def.file == SINK_FILE && self.def.name() == SINK_FN;
        let mut env = Env::new();
        if !is_sink {
            for (name, ty) in self.vocab.receipt_params(self.def) {
                let bound = Bound {
                    name: name.clone(),
                    span: self.def.sig.ident.span(),
                    ty: known(ty, self.owner().to_owned()),
                    carrying: true,
                };
                self.check_scope(&bound, &Scope::Stmts(&body.stmts));
                env.push((name, Some(bound.ty)));
            }
            for input in &self.def.sig.inputs {
                if let syn::FnArg::Typed(typed) = input
                    && let syn::Type::Reference(reference) = &*typed.ty
                    && reference.mutability.is_some()
                    && self.vocab.carries(&reference.elem, Some(self.owner()))
                    && let syn::Pat::Ident(ident) = &*typed.pat
                {
                    self.mut_params.push((ident.ident.to_string(), (*reference.elem).clone()));
                }
            }
        }
        self.walk_block(body, &mut env, Ctx::Kept);
    }

    // ----- types -------------------------------------------------------

    fn ty_carries(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Known(ty, owner) => self.vocab.carries(ty, Some(owner)),
            Ty::Unknown(carrying) => *carrying,
        }
    }

    /// `ty` with a type alias of the tree replaced by its target.
    fn resolve(&self, ty: &Ty) -> Ty {
        if let Ty::Known(written, owner) = ty
            && let Some(name) = super::syntax::type_name(written)
            && let Some(defs) = self.vocab.types.get(&name)
        {
            for def in defs {
                if let super::syntax::TypeDef::Alias(target) = def {
                    return known((*target).clone(), owner.clone());
                }
            }
        }
        ty.clone()
    }

    /// The `index`-th generic type argument of `ty`'s last path segment.
    fn generic(&self, ty: &Ty, index: usize) -> Ty {
        let fallback = Ty::Unknown(self.ty_carries(ty));
        let Ty::Known(written, owner) = self.resolve(ty) else { return fallback };
        let syn::Type::Path(path) = *written else { return fallback };
        let Some(segment) = path.path.segments.last() else { return fallback };
        let syn::PathArguments::AngleBracketed(args) = &segment.arguments else { return fallback };
        args.args
            .iter()
            .filter_map(|arg| match arg {
                syn::GenericArgument::Type(ty) => Some(ty.clone()),
                _ => None,
            })
            .nth(index)
            .map_or(fallback, |ty| known(ty, owner))
    }

    /// Peels `Result`/`Option`/`Box` off `ty` for a pattern that does not
    /// name `Ok`/`Err`/`Some` itself (`?` and `match` unwrap them first).
    fn peel(&self, ty: &Ty) -> Ty {
        let mut ty = self.resolve(ty);
        for _ in 0..8 {
            let name = match &ty {
                Ty::Known(written, _) => super::syntax::type_name(written),
                Ty::Unknown(_) => None,
            };
            match name.as_deref() {
                Some("Result" | "Option" | "Box") => ty = self.resolve(&self.generic(&ty, 0)),
                _ => break,
            }
        }
        ty
    }

    // ----- patterns ----------------------------------------------------

    fn align_top(&self, pat: &syn::Pat, ty: Option<Ty>) -> Aligned {
        let mut out = Aligned::default();
        self.align(pat, &ty.unwrap_or(Ty::Unknown(false)), &mut out);
        out
    }

    fn align(&self, pat: &syn::Pat, ty: &Ty, out: &mut Aligned) {
        match pat {
            syn::Pat::Ident(ident) => {
                if let Some((_, sub)) = &ident.subpat {
                    self.align(sub, ty, out);
                }
                let name = ident.ident.to_string();
                let carrying = self.ty_carries(ty);
                if carrying && ident.by_ref.is_some() {
                    // Round 3 (K-a): `let ref got = producer()?` keeps a
                    // borrow and drops the owned receipt at the end of scope.
                    out.drops.push((
                        ident.ident.span(),
                        format!("binds it by reference as `{name}` (bind it by value)"),
                    ));
                } else if carrying && name.starts_with('_') {
                    out.drops.push((ident.ident.span(), format!("binds it to `{name}`")));
                } else {
                    out.bound.push(Bound {
                        name,
                        span: ident.ident.span(),
                        ty: ty.clone(),
                        carrying,
                    });
                }
            }
            syn::Pat::Wild(wild) => {
                if self.ty_carries(ty) {
                    out.drops.push((wild.underscore_token.span, "binds it to `_`".to_owned()));
                }
            }
            syn::Pat::Tuple(tuple) => {
                let peeled = self.peel(ty);
                let elems: Vec<Ty> = match &peeled {
                    Ty::Known(written, owner) => match &**written {
                        syn::Type::Tuple(types) => {
                            types.elems.iter().map(|t| known(t.clone(), owner.clone())).collect()
                        }
                        _ => Vec::new(),
                    },
                    Ty::Unknown(_) => Vec::new(),
                };
                let fallback = Ty::Unknown(self.ty_carries(&peeled));
                self.align_seq(
                    tuple.elems.iter(),
                    &elems,
                    &fallback,
                    tuple.paren_token.span.open(),
                    out,
                );
            }
            syn::Pat::TupleStruct(tuple) => {
                let last = tuple.path.segments.last().map(|seg| seg.ident.to_string());
                let elems: Vec<Ty> = match last.as_deref() {
                    Some("Ok" | "Some") => vec![self.generic(&self.resolve(ty), 0)],
                    Some("Err") => vec![self.generic(&self.resolve(ty), 1)],
                    _ => self.fields_of(&tuple.path),
                };
                let fallback = Ty::Unknown(self.ty_carries(ty));
                self.align_seq(
                    tuple.elems.iter(),
                    &elems,
                    &fallback,
                    tuple.paren_token.span.open(),
                    out,
                );
            }
            syn::Pat::Struct(pattern) => {
                let owner = self.vocab.type_of_path(&pattern.path, self.owner());
                let candidates = self.vocab.fields_named(&pattern.path, self.owner());
                let Some(syn::Fields::Named(fields)) = candidates.first().copied() else {
                    let fallback = Ty::Unknown(self.ty_carries(ty));
                    for field in &pattern.fields {
                        self.align(&field.pat, &fallback, out);
                    }
                    return;
                };
                let field_ty = |name: &str| {
                    fields.named.iter().find(|f| f.ident.as_ref().is_some_and(|i| i == name)).map(
                        |f| {
                            known(
                                f.ty.clone(),
                                owner.clone().unwrap_or_else(|| self.owner().to_owned()),
                            )
                        },
                    )
                };
                let mut named = Vec::new();
                for field in &pattern.fields {
                    let syn::Member::Named(member) = &field.member else { continue };
                    named.push(member.to_string());
                    let ty = field_ty(&member.to_string()).unwrap_or(Ty::Unknown(false));
                    self.align(&field.pat, &ty, out);
                }
                if let Some(rest) = &pattern.rest {
                    for field in &fields.named {
                        let Some(ident) = &field.ident else { continue };
                        let ty = known(field.ty.clone(), owner.clone().unwrap_or_default());
                        if !named.contains(&ident.to_string()) && self.ty_carries(&ty) {
                            out.drops.push((
                                rest.dot2_token.spans[0],
                                format!("skips its `{ident}` with `..`"),
                            ));
                        }
                    }
                }
            }
            syn::Pat::Or(or) => {
                for case in &or.cases {
                    self.align(case, ty, out);
                }
                // One name per binding: the cases bind the same names.
                let mut seen = std::collections::BTreeSet::new();
                out.bound.retain(|bound| seen.insert(bound.name.clone()));
            }
            syn::Pat::Paren(paren) => self.align(&paren.pat, ty, out),
            syn::Pat::Guard(guard) => self.align(&guard.pat, ty, out),
            syn::Pat::Type(typed) => {
                self.align(&typed.pat, &known((*typed.ty).clone(), self.owner().to_owned()), out);
            }
            // A borrow binds references: the owner keeps the receipt.
            syn::Pat::Reference(reference) => self.align(&reference.pat, &Ty::Unknown(false), out),
            syn::Pat::Slice(slice) => {
                let fallback = Ty::Unknown(self.ty_carries(ty));
                for elem in &slice.elems {
                    self.align(elem, &fallback, out);
                }
            }
            _ => {}
        }
    }

    /// Aligns a tuple-shaped pattern with its element types, including a
    /// `..` that skips some.
    fn align_seq<'p>(
        &self,
        pats: impl Iterator<Item = &'p syn::Pat>,
        elems: &[Ty],
        fallback: &Ty,
        span: Span,
        out: &mut Aligned,
    ) {
        let pats: Vec<&syn::Pat> = pats.collect();
        let rest = pats.iter().position(|pat| matches!(pat, syn::Pat::Rest(_)));
        let ty_at = |index: usize| elems.get(index).cloned().unwrap_or_else(|| fallback.clone());
        match rest {
            None => {
                for (index, pat) in pats.iter().enumerate() {
                    self.align(pat, &ty_at(index), out);
                }
            }
            Some(at) => {
                let after = pats.len() - at - 1;
                for (index, pat) in pats[..at].iter().enumerate() {
                    self.align(pat, &ty_at(index), out);
                }
                let tail_start = elems.len().saturating_sub(after);
                for (offset, pat) in pats[at + 1..].iter().enumerate() {
                    self.align(pat, &ty_at(tail_start + offset), out);
                }
                let skipped = if elems.is_empty() {
                    self.ty_carries(fallback)
                } else {
                    (at..tail_start).any(|index| self.ty_carries(&ty_at(index)))
                };
                if skipped {
                    out.drops.push((span, "skips it with `..`".to_owned()));
                }
            }
        }
    }

    /// The unnamed fields of a tuple struct or variant a pattern names.
    fn fields_of(&self, path: &syn::Path) -> Vec<Ty> {
        let owner =
            self.vocab.type_of_path(path, self.owner()).unwrap_or_else(|| self.owner().to_owned());
        match self.vocab.fields_named(path, self.owner()).first() {
            Some(syn::Fields::Unnamed(fields)) => {
                fields.unnamed.iter().map(|f| known(f.ty.clone(), owner.clone())).collect()
            }
            _ => Vec::new(),
        }
    }

    // ----- what an expression carries ---------------------------------

    /// The type of receipt-bearing value `expr` evaluates to, if any.
    fn carried(&self, expr: &syn::Expr, env: &Env) -> Option<Ty> {
        match expr {
            syn::Expr::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => {
                let name = path.path.segments[0].ident.to_string();
                env.iter().rev().find(|(bound, _)| *bound == name).and_then(|(_, ty)| ty.clone())
            }
            syn::Expr::Call(call) => {
                let syn::Expr::Path(func) = &*call.func else { return None };
                if let Some(def) = self.vocab.path_producers(&func.path, call.args.len()).first() {
                    return return_type(def);
                }
                if is_ctor(&func.path) {
                    return call.args.iter().find_map(|arg| self.carried(arg, env));
                }
                // `take(r)` / `replace(r, x)` on a `&mut` parameter move its
                // receipt out, however the path is spelled (`std::mem::`,
                // `Option::`, an import): the ambiguous direction is the safe
                // one.
                let moves_out = match func.path.segments.last() {
                    Some(last) if last.ident == "take" => call.args.len() == 1,
                    Some(last) if last.ident == "replace" => call.args.len() == 2,
                    _ => false,
                };
                if moves_out {
                    return call.args.first().and_then(|param| self.mut_param(param, env));
                }
                None
            }
            syn::Expr::MethodCall(call) => {
                let name = call.method.to_string();
                if let Some(def) = self.vocab.method_producers(&name, call.args.len()).first() {
                    return return_type(def);
                }
                let argc = call.args.len();
                if (name == "take" && argc == 0)
                    || (matches!(name.as_str(), "replace" | "take_if") && argc == 1)
                {
                    return self.mut_param(&call.receiver, env);
                }
                ADAPTERS
                    .contains(&name.as_str())
                    .then(|| self.carried(&call.receiver, env))
                    .flatten()
            }
            syn::Expr::Try(inner) => self.carried(&inner.expr, env),
            syn::Expr::Paren(inner) => self.carried(&inner.expr, env),
            syn::Expr::Group(inner) => self.carried(&inner.expr, env),
            syn::Expr::Await(inner) => self.carried(&inner.base, env),
            syn::Expr::Struct(literal) => {
                let name = self.vocab.type_of_path(&literal.path, self.owner())?;
                self.vocab.carriers.contains(&name).then(|| known(owner_type(&name), name))
            }
            // A receipt moved into a tuple or an array: the new binding holds
            // it and is followed (round 2, A2) — `carried` mirrors `flows`.
            syn::Expr::Tuple(tuple) => {
                let elems: Vec<Option<Ty>> =
                    tuple.elems.iter().map(|elem| self.carried(elem, env)).collect();
                if elems.iter().all(Option::is_none) {
                    return None;
                }
                let mut types = syn::punctuated::Punctuated::new();
                for elem in elems {
                    types.push(match elem {
                        Some(Ty::Known(written, _)) => *written,
                        Some(Ty::Unknown(true)) => owner_type(super::syntax::SEED),
                        Some(Ty::Unknown(false)) | None => unit_type(),
                    });
                }
                let tuple = syn::TypeTuple {
                    attrs: Vec::new(),
                    paren_token: Default::default(),
                    elems: types,
                };
                Some(known(syn::Type::Tuple(tuple), self.owner().to_owned()))
            }
            syn::Expr::Array(array) => array
                .elems
                .iter()
                .any(|elem| self.carried(elem, env).is_some_and(|ty| self.ty_carries(&ty)))
                .then_some(Ty::Unknown(true)),
            syn::Expr::Match(matched) => {
                let scrutinee = self.carried(&matched.expr, env);
                matched.arms.iter().find_map(|arm| {
                    let aligned = self.align_top(&arm.pat, scrutinee.clone());
                    let mut inner = env.clone();
                    inner.extend(
                        aligned.bound.into_iter().map(|b| (b.name, b.carrying.then_some(b.ty))),
                    );
                    self.carried(&arm.body, &inner)
                })
            }
            syn::Expr::If(branch) => {
                block_tail(&branch.then_branch).and_then(|tail| self.carried(tail, env)).or_else(
                    || branch.else_branch.as_ref().and_then(|(_, other)| self.carried(other, env)),
                )
            }
            syn::Expr::Block(block) => {
                block_tail(&block.block).and_then(|tail| self.carried(tail, env))
            }
            syn::Expr::Unsafe(block) => {
                block_tail(&block.block).and_then(|tail| self.carried(tail, env))
            }
            _ => None,
        }
    }

    /// Whether a value position of `expr` makes a receipt rather than naming
    /// one: a producer, a literal, something moved out of a `&mut`
    /// parameter — inside a tuple, an array, a constructor or an adapter.
    ///
    /// It looks through EVERY kind [`flows`] looks through, and the catch-all
    /// is left to the kinds [`flows`] does not know. The two must agree: a
    /// kind one relays through and the other sends to `carried` reads a pure
    /// move-in as producing, and the head and the chain face then report the
    /// same exit twice (round 3, F-1r2).
    fn produces_in(&self, expr: &syn::Expr, env: &Env) -> bool {
        match expr {
            syn::Expr::Tuple(tuple) => tuple.elems.iter().any(|elem| self.produces_in(elem, env)),
            syn::Expr::Array(array) => array.elems.iter().any(|elem| self.produces_in(elem, env)),
            syn::Expr::Call(call) if matches!(&*call.func, syn::Expr::Path(func) if is_ctor(&func.path)) => {
                call.args.iter().any(|arg| self.produces_in(arg, env))
            }
            syn::Expr::MethodCall(call) if ADAPTERS.contains(&call.method.to_string().as_str()) => {
                self.produces_in(&call.receiver, env)
            }
            syn::Expr::Paren(inner) => self.produces_in(&inner.expr, env),
            syn::Expr::Try(inner) => self.produces_in(&inner.expr, env),
            syn::Expr::Group(inner) => self.produces_in(&inner.expr, env),
            syn::Expr::Await(inner) => self.produces_in(&inner.base, env),
            // The one kind that can itself BE the carrier. Its PARTS are the
            // fields and the functional-update operand (`X { f: 1, ..base }`),
            // which hands the literal a receipt without naming a field. So it
            // produces only when its carrier-ness is its OWN (`WriteReceipt
            // { … }` out of plain parts), and relays whenever any part
            // already carries one (round 3, the lead's ruling on `rest`).
            syn::Expr::Struct(literal) => {
                let parts = || {
                    literal.fields.iter().map(|field| &field.expr).chain(literal.rest.as_deref())
                };
                parts().any(|part| self.produces_in(part, env))
                    || (self.produces(expr).is_some()
                        && parts().all(|part| self.carried(part, env).is_none()))
            }
            syn::Expr::Block(block) => {
                block_tail(&block.block).is_some_and(|tail| self.produces_in(tail, env))
            }
            syn::Expr::Unsafe(block) => {
                block_tail(&block.block).is_some_and(|tail| self.produces_in(tail, env))
            }
            syn::Expr::If(branch) => {
                block_tail(&branch.then_branch).is_some_and(|tail| self.produces_in(tail, env))
                    || branch
                        .else_branch
                        .as_ref()
                        .is_some_and(|(_, other)| self.produces_in(other, env))
            }
            syn::Expr::Match(matched) => {
                matched.arms.iter().any(|arm| self.produces_in(&arm.body, env))
            }
            syn::Expr::Path(_) => false,
            other => self.carried(other, env).is_some_and(|ty| self.ty_carries(&ty)),
        }
    }

    /// The type behind a `&mut` parameter that can hold a receipt, when
    /// `expr` names it and no local shadows it.
    fn mut_param(&self, expr: &syn::Expr, env: &Env) -> Option<Ty> {
        // `&mut *r` is `r` itself (a reborrow in place, not an alias).
        if let syn::Expr::Reference(reference) = expr
            && let syn::Expr::Unary(syn::ExprUnary { op: syn::UnOp::Deref(_), expr, .. }) =
                &*reference.expr
        {
            return self.mut_param(expr, env);
        }
        let syn::Expr::Path(path) = expr else { return None };
        let ident = path.path.get_ident()?.to_string();
        if path.qself.is_some() || env.iter().any(|(bound, _)| *bound == ident) {
            return None;
        }
        let (_, ty) = self.mut_params.iter().find(|(param, _)| *param == ident)?;
        Some(known(ty.clone(), self.owner().to_owned()))
    }

    /// The producer `expr` calls or builds itself, by name.
    fn produces(&self, expr: &syn::Expr) -> Option<String> {
        match expr {
            syn::Expr::Call(call) => {
                let syn::Expr::Path(func) = &*call.func else { return None };
                let defs = self.vocab.path_producers(&func.path, call.args.len());
                defs.first().map(|def| def.name())
            }
            syn::Expr::MethodCall(call) => {
                let name = call.method.to_string();
                let defs = self.vocab.method_producers(&name, call.args.len());
                (!defs.is_empty()).then_some(name)
            }
            syn::Expr::Struct(literal) => {
                let name = self.vocab.type_of_path(&literal.path, self.owner())?;
                self.vocab.carriers.contains(&name).then_some(name)
            }
            _ => None,
        }
    }

    // ----- walking -----------------------------------------------------

    fn walk_block(&mut self, block: &syn::Block, env: &mut Env, ctx: Ctx) {
        let mark = env.len();
        for (index, stmt) in block.stmts.iter().enumerate() {
            match stmt {
                syn::Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        self.walk_expr(&init.expr, env, Ctx::Kept);
                        if let Some((_, diverge)) = &init.diverge {
                            self.walk_expr(diverge, env, Ctx::Kept);
                        }
                    }
                    let ty = local.init.as_ref().and_then(|init| self.carried(&init.expr, env));
                    let aligned = self.align_top(&local.pat, ty);
                    self.bind(aligned, &Scope::Stmts(&block.stmts[index + 1..]), env);
                }
                syn::Stmt::Expr(expr, semi) => {
                    let tail = semi.is_none() && index + 1 == block.stmts.len();
                    if !tail && self.carried(expr, env).is_some_and(|ty| self.ty_carries(&ty)) {
                        self.statement_drop(expr);
                    }
                    self.walk_expr(expr, env, if tail { ctx } else { Ctx::Kept });
                }
                _ => {}
            }
        }
        env.truncate(mark);
    }

    /// R6d for a statement whose value carries a receipt: the value is
    /// dropped where it stands. Named by its producer when it calls one
    /// (under the `?`, parentheses and adapters), on the statement's line.
    fn statement_drop(&mut self, expr: &syn::Expr) {
        let mut inner = expr;
        loop {
            inner = match inner {
                syn::Expr::Try(next) => &next.expr,
                syn::Expr::Paren(next) => &next.expr,
                syn::Expr::MethodCall(call)
                    if ADAPTERS.contains(&call.method.to_string().as_str()) =>
                {
                    &call.receiver
                }
                _ => break,
            };
        }
        let what = self.produces(inner).unwrap_or_default();
        let from =
            if what.is_empty() { "its value carries".to_owned() } else { format!("from `{what}`") };
        let message = format!("a statement drops the receipt {from}{COMPLY_LOST}");
        self.push("R6d", start_line(expr), &what, message);
    }

    /// Reports what `aligned` drops, checks each receipt it binds in
    /// `scope`, and brings its names into `env`.
    fn bind(&mut self, aligned: Aligned, scope: &Scope<'_>, env: &mut Env) {
        for (span, how) in &aligned.drops {
            self.push(
                "R6c",
                line(*span),
                "_",
                format!("a pattern drops a write receipt: it {how}{COMPLY}"),
            );
        }
        for bound in &aligned.bound {
            if bound.carrying {
                self.check_scope(bound, scope);
            }
        }
        env.extend(aligned.bound.into_iter().map(|b| (b.name, b.carrying.then_some(b.ty))));
    }

    fn walk_expr(&mut self, expr: &syn::Expr, env: &mut Env, ctx: Ctx) {
        if ctx == Ctx::Lost
            && let Some(what) = self.produces(expr)
        {
            let at = expr_line(expr);
            self.push(
                "R6d",
                at,
                &what,
                format!("the receipt from `{what}` is used where nothing audits it{COMPLY_LOST}"),
            );
        }
        match expr {
            syn::Expr::Call(call) => {
                self.walk_expr(&call.func, env, Ctx::Lost);
                let path = match &*call.func {
                    syn::Expr::Path(func) => Some(&func.path),
                    _ => None,
                };
                let argc = call.args.len();
                for (index, arg) in call.args.iter().enumerate() {
                    let arg_ctx = match path {
                        Some(path) if is_sink(path) => Ctx::Kept,
                        Some(path) if self.vocab.path_consumes(path, argc, index) => Ctx::Kept,
                        Some(path) if is_ctor(path) => ctx,
                        _ => Ctx::Lost,
                    };
                    self.walk_expr(arg, env, arg_ctx);
                }
            }
            syn::Expr::MethodCall(call) => {
                let name = call.method.to_string();
                let argc = call.args.len();
                let receiver = if ADAPTERS.contains(&name.as_str()) {
                    ctx
                } else if self.vocab.method_consumes(&name, argc, None) {
                    Ctx::Kept
                } else {
                    Ctx::Lost
                };
                self.walk_expr(&call.receiver, env, receiver);
                for (index, arg) in call.args.iter().enumerate() {
                    let kept = self.vocab.method_consumes(&name, argc, Some(index));
                    self.walk_expr(arg, env, if kept { Ctx::Kept } else { Ctx::Lost });
                }
            }
            syn::Expr::Try(inner) => self.walk_expr(&inner.expr, env, ctx),
            syn::Expr::Paren(inner) => self.walk_expr(&inner.expr, env, ctx),
            syn::Expr::Group(inner) => self.walk_expr(&inner.expr, env, ctx),
            syn::Expr::Await(inner) => self.walk_expr(&inner.base, env, ctx),
            syn::Expr::Match(matched) => {
                self.walk_expr(&matched.expr, env, Ctx::Kept);
                let scrutinee = self.carried(&matched.expr, env);
                for arm in &matched.arms {
                    let mark = env.len();
                    let aligned = self.align_top(&arm.pat, scrutinee.clone());
                    // The guard runs after the arm binds and before its body:
                    // an exit there drops what the arm bound (round 3, A2).
                    if let syn::Pat::Guard(guard) = &arm.pat {
                        self.exits_in_guard(&aligned, &guard.guard);
                    }
                    self.bind(aligned, &Scope::Expr(&arm.body), env);
                    if let syn::Pat::Guard(guard) = &arm.pat {
                        self.walk_expr(&guard.guard, env, Ctx::Lost);
                    }
                    self.walk_expr(&arm.body, env, ctx);
                    env.truncate(mark);
                }
            }
            syn::Expr::If(branch) => {
                let mark = env.len();
                self.walk_condition(&branch.cond, &branch.then_branch, env);
                self.walk_block(&branch.then_branch, env, ctx);
                env.truncate(mark);
                if let Some((_, other)) = &branch.else_branch {
                    self.walk_expr(other, env, ctx);
                }
            }
            syn::Expr::While(looped) => {
                let mark = env.len();
                self.walk_condition(&looped.cond, &looped.body, env);
                self.walk_block(&looped.body, env, Ctx::Kept);
                env.truncate(mark);
            }
            syn::Expr::Let(binding) => self.walk_expr(&binding.expr, env, Ctx::Kept),
            syn::Expr::Block(block) => self.walk_block(&block.block, env, ctx),
            syn::Expr::Unsafe(block) => self.walk_block(&block.block, env, ctx),
            syn::Expr::Async(block) => self.walk_block(&block.block, env, Ctx::Kept),
            syn::Expr::Const(block) => self.walk_block(&block.block, env, Ctx::Kept),
            syn::Expr::Loop(looped) => self.walk_block(&looped.body, env, Ctx::Kept),
            // A collection of receipts is not a supported shape (round 3,
            // A1): iterating a producer's result directly is R6d, and the
            // loop pattern binds nothing the rule follows.
            syn::Expr::ForLoop(looped) => {
                self.walk_expr(&looped.expr, env, Ctx::Lost);
                let mark = env.len();
                let aligned = self.align_top(&looped.pat, None);
                env.extend(aligned.bound.into_iter().map(|b| (b.name, None)));
                self.walk_block(&looped.body, env, Ctx::Kept);
                env.truncate(mark);
            }
            syn::Expr::Closure(closure) => {
                let mark = env.len();
                for input in &closure.inputs {
                    let aligned = self.align_top(input, None);
                    env.extend(aligned.bound.into_iter().map(|b| (b.name, None)));
                }
                self.walk_expr(&closure.body, env, Ctx::Kept);
                env.truncate(mark);
            }
            syn::Expr::Return(returned) => {
                if let Some(value) = &returned.expr {
                    self.walk_expr(value, env, Ctx::Kept);
                }
            }
            syn::Expr::Break(broken) => {
                if let Some(value) = &broken.expr {
                    self.walk_expr(value, env, Ctx::Kept);
                }
            }
            syn::Expr::Tuple(tuple) => {
                for elem in &tuple.elems {
                    self.walk_expr(elem, env, ctx);
                }
            }
            syn::Expr::Array(array) => {
                for elem in &array.elems {
                    self.walk_expr(elem, env, ctx);
                }
            }
            syn::Expr::Struct(literal) => {
                for field in &literal.fields {
                    self.walk_expr(&field.expr, env, ctx);
                }
                if let Some(rest) = &literal.rest {
                    self.walk_expr(rest, env, Ctx::Lost);
                }
            }
            syn::Expr::Assign(assign) => {
                self.walk_expr(&assign.left, env, Ctx::Lost);
                self.walk_expr(&assign.right, env, Ctx::Lost);
            }
            syn::Expr::Binary(binary) => {
                self.walk_expr(&binary.left, env, Ctx::Lost);
                self.walk_expr(&binary.right, env, Ctx::Lost);
            }
            syn::Expr::Unary(unary) => self.walk_expr(&unary.expr, env, Ctx::Lost),
            syn::Expr::Reference(reference) => self.walk_expr(&reference.expr, env, Ctx::Lost),
            syn::Expr::Field(field) => self.walk_expr(&field.base, env, Ctx::Lost),
            syn::Expr::Index(index) => {
                self.walk_expr(&index.expr, env, Ctx::Lost);
                self.walk_expr(&index.index, env, Ctx::Lost);
            }
            syn::Expr::Cast(cast) => self.walk_expr(&cast.expr, env, Ctx::Lost),
            syn::Expr::Range(range) => {
                for end in [&range.start, &range.end].into_iter().flatten() {
                    self.walk_expr(end, env, Ctx::Lost);
                }
            }
            syn::Expr::Repeat(repeat) => self.walk_expr(&repeat.expr, env, Ctx::Lost),
            _ => {}
        }
    }

    /// The `let`s of an `if`/`while` condition (a `&&` chain included):
    /// each binds for `body`; the rest of the condition is a plain operand.
    fn walk_condition(&mut self, cond: &syn::Expr, body: &syn::Block, env: &mut Env) {
        let chain = operands(cond);
        for (index, operand) in chain.iter().enumerate() {
            match operand {
                syn::Expr::Let(binding) => {
                    self.walk_expr(&binding.expr, env, Ctx::Kept);
                    let ty = self.carried(&binding.expr, env);
                    let aligned = self.align_top(&binding.pat, ty);
                    let produced: Vec<(String, usize)> = aligned
                        .bound
                        .iter()
                        .filter(|bound| bound.carrying)
                        .map(|bound| (bound.name.clone(), line(bound.span)))
                        .collect();
                    // A `let` that only MOVES a live receipt in is the head
                    // face's (it scans the whole head); the chain face owns
                    // what a `let` PRODUCES (round 2, F-1).
                    let live = |name: &str| {
                        env.iter()
                            .rev()
                            .find(|(bound, _)| bound == name)
                            .is_some_and(|(_, ty)| ty.is_some())
                    };
                    let moved_in =
                        env.iter().any(|(bound, _)| live(bound) && flows(&binding.expr, bound));
                    if !produced.is_empty() && (!moved_in || self.produces_in(&binding.expr, env)) {
                        self.exits_in_chain(&produced, &chain[index + 1..]);
                    }
                    self.bind(aligned, &Scope::Stmts(&body.stmts), env);
                }
                other => self.walk_expr(other, env, Ctx::Lost),
            }
        }
    }

    // ----- accounting for one binding ------------------------------------

    fn check_scope(&mut self, bound: &Bound, scope: &Scope<'_>) {
        let name = bound.name.as_str();
        let at = line(bound.span);
        let site = format!("{}:{}:{name}", self.def.file, self.def.name());
        self.followed.push(site.clone());
        match scope {
            // A `match` arm whose body is a block is a statement scope like any
            // other (bead agctl-meqv round 2, A1): R6e runs inside it.
            Scope::Expr(syn::Expr::Block(block)) => {
                self.check_stmts(bound, &block.block.stmts, site)
            }
            Scope::Expr(syn::Expr::Unsafe(block)) => {
                self.check_stmts(bound, &block.block.stmts, site)
            }
            // A single-expression arm is a one-statement scope: nothing stands
            // between the binding and the use but the statement itself.
            Scope::Expr(expr) => {
                if !(flows(expr, name) || self.uses(|v| v.visit_expr(expr), name)) {
                    self.never(bound, at);
                    return;
                }
                // Not recorded as `exit_checked`: that list proves the
                // statement scan ran, and none does here (round 3, A4).
                self.exits_in_head(expr, name, at, &site);
                self.descend(expr, name, at, &site);
                self.exits_in_audit_call(|v| v.visit_expr(expr), name, at);
            }
            Scope::Stmts(stmts) => self.check_stmts(bound, stmts, site),
        }
    }

    /// R6e over a `match` arm's guard, for each receipt the arm binds.
    fn exits_in_guard(&mut self, aligned: &Aligned, guard: &syn::Expr) {
        let mut exits = EarlyExit::default();
        exits.visit_expr(guard);
        let Some((what, exit_line)) = exits.first else { return };
        for bound in aligned.bound.iter().filter(|bound| bound.carrying) {
            let name = &bound.name;
            let at = line(bound.span);
            self.push(
                "R6e",
                exit_line,
                name,
                format!(
                    "`{what}` in the arm's guard can leave before the receipt `{name}` (bound at line {at}) is audited{COMPLY}"
                ),
            );
        }
    }

    /// R6c and R6e over a statement list: the first statement that uses the
    /// receipt, no early exit in any statement before it, and none inside the
    /// arguments of the call that takes it.
    fn check_stmts(&mut self, bound: &Bound, stmts: &[syn::Stmt], site: String) {
        let name = bound.name.as_str();
        let at = line(bound.span);
        let Some(used) = self.first_use(stmts, name) else {
            self.never(bound, at);
            return;
        };
        self.exit_checked.push(site.clone());
        self.scan_stmts(stmts, used, name, at, &site);
        // Once, at the top: it visits the whole subtree of the statement,
        // the audit calls of every descended body included.
        self.exits_in_audit_call(|v| v.visit_stmt(&stmts[used]), name, at);
    }

    /// The index of the first statement that uses `name`.
    fn first_use(&self, stmts: &[syn::Stmt], name: &str) -> Option<usize> {
        let last = stmts.len().checked_sub(1);
        stmts.iter().enumerate().position(|(index, stmt)| {
            let tail_flows = Some(index) == last
                && matches!(stmt, syn::Stmt::Expr(expr, None) if flows(expr, name));
            tail_flows || self.uses(|v| v.visit_stmt(stmt), name)
        })
    }

    /// R6e over one statement list that holds the use: the statement scan
    /// before `used`, the head scan of `used`, then the descent into the
    /// body of `used` that holds the use.
    fn scan_stmts(&mut self, stmts: &[syn::Stmt], used: usize, name: &str, at: usize, site: &str) {
        for stmt in &stmts[..used] {
            let mut exits = EarlyExit::default();
            exits.visit_stmt(stmt);
            if let Some((what, exit_line)) = exits.first {
                self.push(
                    "R6e",
                    exit_line,
                    name,
                    format!(
                        "`{what}` can leave before the receipt `{name}` (bound at line {at}) is audited{COMPLY}"
                    ),
                );
            }
        }
        let top = match &stmts[used] {
            syn::Stmt::Expr(expr, _) => Some(expr),
            syn::Stmt::Local(local) => local.init.as_ref().map(|init| &*init.expr),
            _ => None,
        };
        if let Some(top) = top {
            self.exits_in_head(top, name, at, site);
            self.descend(top, name, at, site);
        }
    }

    /// Where the use sits INSIDE the statement `top` whose head was just
    /// scanned: the branch, arm or body that holds it, scanned as a statement
    /// list of its own (`if c { step()?; audit::append(p, r)?; }`). A head
    /// that hands the receipt on (`if let Some(r2) = r`, `match r { … }`)
    /// ends the descent: the new binding is checked on its own.
    fn descend(&mut self, top: &syn::Expr, name: &str, at: usize, site: &str) {
        let hands_on = match top {
            syn::Expr::If(branch) => moves_in(&branch.cond, name),
            syn::Expr::While(looped) => moves_in(&looped.cond, name),
            syn::Expr::Match(matched) => flows(&matched.expr, name),
            _ => false,
        };
        if hands_on {
            return;
        }
        match top {
            syn::Expr::If(branch) => {
                self.enter(&branch.then_branch, name, at, site);
                match branch.else_branch.as_ref().map(|(_, other)| &**other) {
                    Some(other @ syn::Expr::If(_)) if self.uses(|v| v.visit_expr(other), name) => {
                        self.exits_in_head(other, name, at, site);
                        self.descend(other, name, at, site);
                    }
                    Some(syn::Expr::Block(block)) => self.enter(&block.block, name, at, site),
                    _ => {}
                }
            }
            syn::Expr::While(looped) => self.enter(&looped.body, name, at, site),
            syn::Expr::Loop(looped) => self.enter(&looped.body, name, at, site),
            syn::Expr::Block(block) => self.enter(&block.block, name, at, site),
            syn::Expr::Unsafe(block) => self.enter(&block.block, name, at, site),
            syn::Expr::Match(matched) => {
                for arm in &matched.arms {
                    match &*arm.body {
                        syn::Expr::Block(block) => self.enter(&block.block, name, at, site),
                        syn::Expr::Unsafe(block) => self.enter(&block.block, name, at, site),
                        body if self.uses(|v| v.visit_expr(body), name) => {
                            self.exits_in_head(body, name, at, site);
                            self.descend(body, name, at, site);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// A body entered by [`Self::descend`], when it holds the use.
    fn enter(&mut self, block: &syn::Block, name: &str, at: usize, site: &str) {
        let Some(used) = self.first_use(&block.stmts, name) else { return };
        self.exit_checked.push(format!("{site}:body"));
        self.scan_stmts(&block.stmts, used, name, at, site);
    }

    /// R6e over the HEAD of the statement that accounts for a live receipt:
    /// the condition of an `if`/`while` (a `&&` chain or not) and the
    /// scrutinee of a `match`. The receipt is live until the call that takes
    /// it, so a `?`, `return`, `break` or `continue` evaluated before that
    /// call drops it — `if review_ok()? { audit::append(p, receipt)?; }`,
    /// and either side of a `let` of the chain that moves it in (`if x()? &&
    /// let Some(r) = receipt`); none is a take, so that whole head counts.
    fn exits_in_head(&mut self, top: &syn::Expr, name: &str, at: usize, site: &str) {
        let head = match top {
            syn::Expr::If(branch) => operands(&branch.cond),
            syn::Expr::While(looped) => operands(&looped.cond),
            syn::Expr::Match(matched) => vec![&*matched.expr],
            _ => return,
        };
        self.exit_checked.push(format!("{site}:head"));
        // One visitor over the operands in evaluation order, stopped at the
        // call that takes the receipt: that call's arguments and receiver
        // are the call face's, and what runs after it runs after the audit.
        let mut exits = EarlyExit { stop: Some((self.vocab, name)), ..EarlyExit::default() };
        for operand in head {
            exits.visit_expr(operand);
            if exits.stopped && exits.first.is_none() {
                return;
            }
            if let Some((what, exit_line)) = exits.first {
                self.push(
                    "R6e",
                    exit_line,
                    name,
                    format!(
                        "`{what}` in the head of the statement that accounts for the receipt `{name}` (bound at line {at}) can leave before it is audited{COMPLY}"
                    ),
                );
                return;
            }
        }
    }

    /// R6e over a let chain for the receipts one of its `let`s PRODUCES:
    /// they are live from the next operand on, so an exit in any later
    /// operand drops them (`if let Ok((r, _)) = i.install(f) && x()? {…}`).
    /// An exit LEFT of the producing `let` drops nothing: no receipt exists
    /// yet. A `let` that only moves a live receipt in is not scanned here
    /// ([`Self::walk_condition`]); one that both moves in and produces is,
    /// so an exit right of it is reported by both faces (a written residual).
    fn exits_in_chain(&mut self, bound: &[(String, usize)], later: &[&syn::Expr]) {
        for (name, _) in bound {
            self.exit_checked.push(format!("{}:{}:{name}:chain", self.def.file, self.def.name()));
        }
        for operand in later {
            let mut exits = EarlyExit::default();
            exits.visit_expr(operand);
            if let Some((what, exit_line)) = exits.first {
                for (name, at) in bound {
                    self.push(
                        "R6e",
                        exit_line,
                        name,
                        format!(
                            "`{what}` later in the let chain can leave before the receipt `{name}` (bound at line {at}) is audited{COMPLY}"
                        ),
                    );
                }
                return;
            }
        }
    }

    /// R6e inside the statement that audits: Rust evaluates a call's
    /// arguments left to right into temporaries, so a `?` in ANY other
    /// argument of the call that takes the receipt drops it
    /// (`audit::append(paths()?, receipt)?`). The call's own trailing `?`
    /// is not one: by then the receipt has been moved in (round 2, A5).
    fn exits_in_audit_call(
        &mut self,
        visit: impl FnOnce(&mut AuditCall<'_, '_>),
        name: &str,
        at: usize,
    ) {
        let mut call = AuditCall { vocab: self.vocab, name, exits: Vec::new() };
        visit(&mut call);
        for (what, exit_line) in call.exits {
            self.push(
                "R6e",
                exit_line,
                name,
                format!(
                    "`{what}` inside the call that takes the receipt `{name}` (bound at line {at}) can leave before it is audited{COMPLY}"
                ),
            );
        }
    }

    fn never(&mut self, bound: &Bound, at: usize) {
        let name = &bound.name;
        self.push(
            "R6c",
            at,
            name,
            format!(
                "the receipt `{name}` never reaches `audit::append`, a consumer, or the caller{COMPLY}"
            ),
        );
    }

    fn uses(&self, visit: impl FnOnce(&mut Uses<'_, '_>), name: &str) -> bool {
        let mut uses = Uses { vocab: self.vocab, name, found: false };
        visit(&mut uses);
        uses.found
    }
}

/// Whether `name` is handed on anywhere in a subtree: to `audit::append`,
/// to a consumer, out through a `return`/`break`/closure/block tail, or into
/// a new binding (which is then checked on its own).
struct Uses<'v, 'n> {
    vocab: &'v Vocabulary<'v>,
    name: &'n str,
    found: bool,
}

impl<'ast> Visit<'ast> for Uses<'_, '_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if local.init.as_ref().is_some_and(|init| flows(&init.expr, self.name)) {
            self.found = true;
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_return(&mut self, returned: &'ast syn::ExprReturn) {
        if returned.expr.as_deref().is_some_and(|value| flows(value, self.name)) {
            self.found = true;
        }
        syn::visit::visit_expr_return(self, returned);
    }

    fn visit_expr_break(&mut self, broken: &'ast syn::ExprBreak) {
        if broken.expr.as_deref().is_some_and(|value| flows(value, self.name)) {
            self.found = true;
        }
        syn::visit::visit_expr_break(self, broken);
    }

    fn visit_expr_match(&mut self, matched: &'ast syn::ExprMatch) {
        if flows(&matched.expr, self.name)
            || matched.arms.iter().any(|arm| flows(&arm.body, self.name))
        {
            self.found = true;
        }
        syn::visit::visit_expr_match(self, matched);
    }

    fn visit_expr_let(&mut self, binding: &'ast syn::ExprLet) {
        if flows(&binding.expr, self.name) {
            self.found = true;
        }
        syn::visit::visit_expr_let(self, binding);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        if flows(&closure.body, self.name) {
            self.found = true;
        }
        syn::visit::visit_expr_closure(self, closure);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        if block_tail(block).is_some_and(|tail| flows(tail, self.name)) {
            self.found = true;
        }
        syn::visit::visit_block(self, block);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = &*call.func {
            let argc = call.args.len();
            let taken = call.args.iter().enumerate().any(|(index, arg)| {
                flows_into_call(arg, self.name)
                    && (is_sink(&func.path) || self.vocab.path_consumes(&func.path, argc, index))
            });
            if taken {
                self.found = true;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        let argc = call.args.len();
        let receiver =
            flows(&call.receiver, self.name) && self.vocab.method_consumes(&name, argc, None);
        let argument = call.args.iter().enumerate().any(|(index, arg)| {
            flows_into_call(arg, self.name) && self.vocab.method_consumes(&name, argc, Some(index))
        });
        if receiver || argument {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// The early exits inside the arguments (and receiver) of every call in a
/// statement that takes `name`: the sink or a consumer.
struct AuditCall<'v, 'n> {
    vocab: &'v Vocabulary<'v>,
    name: &'n str,
    exits: Vec<(&'static str, usize)>,
}

impl AuditCall<'_, '_> {
    fn scan<'e>(&mut self, others: impl Iterator<Item = &'e syn::Expr>) {
        for other in others {
            let mut exits = EarlyExit::default();
            exits.visit_expr(other);
            if let Some(found) = exits.first {
                self.exits.push(found);
            }
        }
    }
}

impl<'ast> Visit<'ast> for AuditCall<'_, '_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(func) = &*call.func {
            let argc = call.args.len();
            let taken = call.args.iter().enumerate().position(|(index, arg)| {
                flows_into_call(arg, self.name)
                    && (is_sink(&func.path) || self.vocab.path_consumes(&func.path, argc, index))
            });
            if let Some(taken) = taken {
                self.scan(
                    call.args.iter().enumerate().filter(|(i, _)| *i != taken).map(|(_, a)| a),
                );
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        let argc = call.args.len();
        let by_receiver =
            flows(&call.receiver, self.name) && self.vocab.method_consumes(&name, argc, None);
        let by_arg = call.args.iter().enumerate().position(|(index, arg)| {
            flows_into_call(arg, self.name) && self.vocab.method_consumes(&name, argc, Some(index))
        });
        if by_receiver {
            self.scan(call.args.iter());
        } else if let Some(taken) = by_arg {
            let others = call.args.iter().enumerate().filter(|(i, _)| *i != taken).map(|(_, a)| a);
            self.scan(std::iter::once(&*call.receiver).chain(others));
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// The first early exit in a statement: a `?` or a `return` anywhere
/// outside a closure or a nested item, a `break`/`continue` outside a loop
/// nested in the statement. With `stop`, the visit ends at the first call
/// that takes the receipt `stop` names (the head face, round 2, F-2).
#[derive(Default)]
struct EarlyExit<'v, 'n> {
    loops: usize,
    first: Option<(&'static str, usize)>,
    stop: Option<(&'v Vocabulary<'v>, &'n str)>,
    stopped: bool,
}

impl EarlyExit<'_, '_> {
    fn note(&mut self, what: &'static str, span: Span) {
        if self.first.is_none() && !self.stopped {
            self.first = Some((what, line(span)));
        }
    }
}

impl<'ast> Visit<'ast> for EarlyExit<'_, '_> {
    fn visit_item(&mut self, _: &'ast syn::Item) {}

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        match self.stop {
            Some((vocab, name)) if call_takes(vocab, call, name) => self.stopped = true,
            _ if !self.stopped => syn::visit::visit_expr_call(self, call),
            _ => {}
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        match self.stop {
            Some((vocab, name)) if method_takes(vocab, call, name) => self.stopped = true,
            _ if !self.stopped => syn::visit::visit_expr_method_call(self, call),
            _ => {}
        }
    }

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}

    fn visit_expr_try(&mut self, tried: &'ast syn::ExprTry) {
        self.note("?", tried.question_token.span);
        syn::visit::visit_expr_try(self, tried);
    }

    fn visit_expr_return(&mut self, returned: &'ast syn::ExprReturn) {
        self.note("return", returned.return_token.span);
        syn::visit::visit_expr_return(self, returned);
    }

    fn visit_expr_break(&mut self, broken: &'ast syn::ExprBreak) {
        if self.loops == 0 {
            self.note("break", broken.break_token.span);
        }
        syn::visit::visit_expr_break(self, broken);
    }

    fn visit_expr_continue(&mut self, continued: &'ast syn::ExprContinue) {
        if self.loops == 0 {
            self.note("continue", continued.continue_token.span);
        }
        syn::visit::visit_expr_continue(self, continued);
    }

    // Source order is not evaluation order across ALTERNATIVES: a stop
    // reached on one branch, on the right of `&&`/`||`, or in a loop body
    // survives only where the audit surely ran (every branch stopped).

    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        if self.stopped {
            return;
        }
        self.visit_expr(&branch.cond);
        if self.stopped {
            return;
        }
        self.visit_block(&branch.then_branch);
        let then_stopped = std::mem::take(&mut self.stopped);
        if let Some((_, other)) = &branch.else_branch {
            self.visit_expr(other);
            self.stopped &= then_stopped;
        }
    }

    fn visit_expr_match(&mut self, matched: &'ast syn::ExprMatch) {
        if self.stopped {
            return;
        }
        self.visit_expr(&matched.expr);
        if self.stopped {
            return;
        }
        let mut every = !matched.arms.is_empty();
        for arm in &matched.arms {
            if let syn::Pat::Guard(guarded) = &arm.pat {
                self.visit_expr(&guarded.guard);
            }
            self.visit_expr(&arm.body);
            every &= std::mem::take(&mut self.stopped);
        }
        self.stopped = every;
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if self.stopped {
            return;
        }
        self.visit_expr(&binary.left);
        if self.stopped {
            return;
        }
        self.visit_expr(&binary.right);
        if matches!(binary.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) {
            self.stopped = false;
        }
    }

    fn visit_expr_loop(&mut self, looped: &'ast syn::ExprLoop) {
        if self.stopped {
            return;
        }
        self.loops += 1;
        self.visit_block(&looped.body);
        self.stopped = false;
        self.loops -= 1;
    }

    fn visit_expr_while(&mut self, looped: &'ast syn::ExprWhile) {
        if self.stopped {
            return;
        }
        self.loops += 1;
        self.visit_expr(&looped.cond);
        let cond_stopped = self.stopped;
        self.visit_block(&looped.body);
        self.stopped = cond_stopped;
        self.loops -= 1;
    }

    fn visit_expr_for_loop(&mut self, looped: &'ast syn::ExprForLoop) {
        if self.stopped {
            return;
        }
        self.loops += 1;
        self.visit_expr(&looped.expr);
        let iter_stopped = self.stopped;
        self.visit_block(&looped.body);
        self.stopped = iter_stopped;
        self.loops -= 1;
    }
}

/// Whether `expr`'s VALUE is `name`, or is built from it: `r`, `Ok((r, x))`,
/// `CodexWrite::Landed { receipt: r, .. }`, a block/`if`/`match` whose result
/// is one of those, an adapter over one.
fn flows(expr: &syn::Expr, name: &str) -> bool {
    match expr {
        syn::Expr::Path(path) => path.qself.is_none() && path.path.is_ident(name),
        syn::Expr::Paren(inner) => flows(&inner.expr, name),
        syn::Expr::Group(inner) => flows(&inner.expr, name),
        syn::Expr::Try(inner) => flows(&inner.expr, name),
        syn::Expr::Await(inner) => flows(&inner.base, name),
        syn::Expr::Tuple(tuple) => tuple.elems.iter().any(|elem| flows(elem, name)),
        syn::Expr::Array(array) => array.elems.iter().any(|elem| flows(elem, name)),
        // A `rest` operand moves from the base only the fields the literal
        // does NOT name, so it hands the WHOLE base on only when the literal
        // names none. A literal that names a field beside its `rest` leaves
        // the base live, and the base goes on being scanned (residual :82).
        syn::Expr::Struct(literal) => {
            literal.fields.iter().any(|field| flows(&field.expr, name))
                || (literal.fields.is_empty()
                    && literal.rest.as_ref().is_some_and(|rest| flows(rest, name)))
        }
        syn::Expr::Call(call) => {
            matches!(&*call.func, syn::Expr::Path(func) if is_ctor(&func.path))
                && call.args.iter().any(|arg| flows(arg, name))
        }
        syn::Expr::MethodCall(call) => {
            ADAPTERS.contains(&call.method.to_string().as_str()) && flows(&call.receiver, name)
        }
        syn::Expr::Block(block) => block_tail(&block.block).is_some_and(|tail| flows(tail, name)),
        syn::Expr::Unsafe(block) => block_tail(&block.block).is_some_and(|tail| flows(tail, name)),
        syn::Expr::If(branch) => {
            block_tail(&branch.then_branch).is_some_and(|tail| flows(tail, name))
                || branch.else_branch.as_ref().is_some_and(|(_, other)| flows(other, name))
        }
        syn::Expr::Match(matched) => matched.arms.iter().any(|arm| flows(&arm.body, name)),
        _ => false,
    }
}

/// [`flows`], plus a field of the binding (`got.receipt`): an argument of a
/// call that takes a receipt moves the field out, so the binding's receipt
/// is handed on (round 2, A4 (a)). Only here: a field moved into a `let`
/// or a tail is not followed, so it does not count as a use.
fn flows_into_call(expr: &syn::Expr, name: &str) -> bool {
    match expr {
        syn::Expr::Field(field) => flows_into_call(&field.base, name),
        other => flows(other, name),
    }
}

/// Whether `call` takes `name`: by an argument, into the sink or a consumer
/// (the test [`Uses`] applies).
fn call_takes(vocab: &Vocabulary<'_>, call: &syn::ExprCall, name: &str) -> bool {
    let syn::Expr::Path(func) = &*call.func else { return false };
    let argc = call.args.len();
    call.args.iter().enumerate().any(|(index, arg)| {
        flows_into_call(arg, name)
            && (is_sink(&func.path) || vocab.path_consumes(&func.path, argc, index))
    })
}

/// Whether the method `call` takes `name`, as its receiver or an argument.
fn method_takes(vocab: &Vocabulary<'_>, call: &syn::ExprMethodCall, name: &str) -> bool {
    let method = call.method.to_string();
    let argc = call.args.len();
    (flows(&call.receiver, name) && vocab.method_consumes(&method, argc, None))
        || call.args.iter().enumerate().any(|(index, arg)| {
            flows_into_call(arg, name) && vocab.method_consumes(&method, argc, Some(index))
        })
}

/// The operands of an `if`/`while` condition, left to right: a `&&` chain
/// flattened, parentheses looked through; any other condition is one operand.
fn operands(cond: &syn::Expr) -> Vec<&syn::Expr> {
    match cond {
        syn::Expr::Binary(binary) if matches!(binary.op, syn::BinOp::And(_)) => {
            let mut all = operands(&binary.left);
            all.extend(operands(&binary.right));
            all
        }
        syn::Expr::Paren(inner) => operands(&inner.expr),
        other => vec![other],
    }
}

/// Whether a `let` of an `if`/`while` condition moves `name` in.
fn moves_in(cond: &syn::Expr, name: &str) -> bool {
    operands(cond)
        .into_iter()
        .any(|operand| matches!(operand, syn::Expr::Let(binding) if flows(&binding.expr, name)))
}

/// A block's tail expression.
fn block_tail(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.last() {
        Some(syn::Stmt::Expr(expr, None)) => Some(expr),
        _ => None,
    }
}

/// `codex::audit::append`, by its qualified spelling.
fn is_sink(path: &syn::Path) -> bool {
    path.segments.last().is_some_and(|seg| seg.ident == SINK_FN)
        && qualifier(path).as_deref() == Some("audit")
}

/// A tuple-struct or variant constructor: `Ok`, `Some`, `Err`, or a path
/// whose last segment is capitalised.
fn is_ctor(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|seg| seg.ident.to_string().starts_with(|c: char| c.is_ascii_uppercase()))
}

/// `()`.
fn unit_type() -> syn::Type {
    syn::Type::Tuple(syn::TypeTuple {
        attrs: Vec::new(),
        paren_token: Default::default(),
        elems: syn::punctuated::Punctuated::new(),
    })
}

/// A producer's declared return type, read inside its owner.
fn return_type(def: &FnDef<'_>) -> Option<Ty> {
    match &def.sig.output {
        syn::ReturnType::Type(_, ty) => Some(known((**ty).clone(), def.owner.clone())),
        syn::ReturnType::Default => None,
    }
}

/// The line of an expression's first token, for every kind `carried` can
/// hold a receipt in (round 2, F-3: never line 0 for a statement).
fn start_line(expr: &syn::Expr) -> usize {
    match expr {
        syn::Expr::Path(path) => path.path.segments.first().map_or(0, |seg| line(seg.ident.span())),
        syn::Expr::Paren(inner) => line(inner.paren_token.span.open()),
        syn::Expr::Group(inner) => start_line(&inner.expr),
        syn::Expr::Try(inner) => start_line(&inner.expr),
        syn::Expr::Await(inner) => start_line(&inner.base),
        syn::Expr::Field(field) => start_line(&field.base),
        syn::Expr::Tuple(tuple) => line(tuple.paren_token.span.open()),
        syn::Expr::Array(array) => line(array.bracket_token.span.open()),
        syn::Expr::Call(call) => start_line(&call.func),
        syn::Expr::MethodCall(call) => start_line(&call.receiver),
        syn::Expr::Match(matched) => line(matched.match_token.span),
        syn::Expr::If(branch) => line(branch.if_token.span),
        syn::Expr::Block(block) => line(block.block.brace_token.span.open()),
        syn::Expr::Unsafe(block) => line(block.unsafe_token.span),
        other => expr_line(other),
    }
}

/// The line an expression starts on, from its first token that carries one.
fn expr_line(expr: &syn::Expr) -> usize {
    match expr {
        syn::Expr::Call(call) => match &*call.func {
            syn::Expr::Path(func) => {
                func.path.segments.first().map_or(0, |seg| line(seg.ident.span()))
            }
            other => expr_line(other),
        },
        syn::Expr::MethodCall(call) => line(call.method.span()),
        syn::Expr::Struct(literal) => {
            literal.path.segments.first().map_or(0, |seg| line(seg.ident.span()))
        }
        _ => 0,
    }
}
