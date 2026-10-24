//! High-level query methods shared by the blocking and async sockets.

/// Number of attempts for dumps interrupted by concurrent changes.
pub(crate) const DUMP_RETRIES: u32 = 40;

/// Delay before retry `attempt` of an interrupted dump: immediate at first,
/// then exponential backoff up to 50 ms (about 1.5 s in total).
pub(crate) fn backoff(attempt: u32) -> Option<std::time::Duration> {
    (attempt >= 3).then(|| {
        std::time::Duration::from_micros(100u64 << (attempt - 3).min(9))
            .min(std::time::Duration::from_millis(50))
    })
}

/// The result of a dump that resets state (counters, quotas). Such a dump
/// is not retried when interrupted, since the reset is not repeatable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetDump<T> {
    /// The objects, with their values before the reset.
    pub items: Vec<T>,
    /// The dump was interrupted by a concurrent ruleset change: some
    /// objects may be missing or repeated (missing ones may have been reset
    /// anyway).
    pub interrupted: bool,
}

impl<T> IntoIterator for ResetDump<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

macro_rules! sync_sleep {
    ($attempt:expr) => {
        if let Some(d) = $crate::client::backoff($attempt) {
            std::thread::sleep(d);
        }
    };
}
pub(crate) use sync_sleep;

#[allow(unused_macros)]
macro_rules! async_sleep {
    ($attempt:expr) => {
        if let Some(d) = $crate::client::backoff($attempt) {
            ::tokio::time::sleep(d).await;
        }
    };
}
#[allow(unused_imports)]
pub(crate) use async_sleep;

macro_rules! sync_await {
    ($e:expr) => {
        $e
    };
}
pub(crate) use sync_await;

#[allow(unused_macros)]
macro_rules! async_await {
    ($e:expr) => {
        $e.await
    };
}
#[allow(unused_imports)]
pub(crate) use async_await;

macro_rules! client_methods {
    ($ty:ty, sync) => {
        $crate::client::client_methods!(@impl $ty, [], sync_await, sync_sleep);
    };
    ($ty:ty, async) => {
        $crate::client::client_methods!(@impl $ty, [async], async_await, async_sleep);
    };
    (@impl $ty:ty, [$($kw:tt)*], $aw:ident, $sleep:ident) => {
        #[allow(clippy::too_many_arguments)]
        impl $ty {
            /// Run a dump, retrying if it is interrupted by concurrent
            /// ruleset changes.
            pub $($kw)* fn dump<T: $crate::proto::Decode>(&mut self, req: &$crate::proto::Request) -> $crate::Result<Vec<T>> {
                for attempt in 0..$crate::client::DUMP_RETRIES {
                    $crate::client::$sleep!(attempt);
                    let (v, interrupted) = $crate::client::$aw!(self.dump_vec_once::<T>(req))?;
                    if !interrupted {
                        return Ok(v);
                    }
                }
                Err($crate::Error::DumpInterrupted)
            }

            /// Run a non-dump request expecting exactly one object.
            pub $($kw)* fn get<T: $crate::proto::Decode>(&mut self, req: &$crate::proto::Request) -> $crate::Result<T> {
                let (v, _) = $crate::client::$aw!(self.dump_vec_once::<T>(req))?;
                v.into_iter().next().ok_or($crate::Error::malformed("empty reply"))
            }

            /// The current ruleset generation id.
            pub $($kw)* fn get_gen(&mut self) -> $crate::Result<u32> {
                let g: $crate::Gen = $crate::client::$aw!(self.get(&$crate::proto::Request::generation()))?;
                Ok(g.id)
            }

            /// List tables of a family ([`Family::Unspec`](crate::Family::Unspec) for all).
            pub $($kw)* fn list_tables(&mut self, family: $crate::Family) -> $crate::Result<Vec<$crate::Table>> {
                $crate::client::$aw!(self.dump(&$crate::proto::Request::tables(family)))
            }

            /// Get a table by name.
            pub $($kw)* fn get_table(&mut self, family: $crate::Family, name: &str) -> $crate::Result<$crate::Table> {
                $crate::client::$aw!(self.get(&$crate::proto::Request::table(family, name)))
            }

            /// List chains, optionally of a single table.
            pub $($kw)* fn list_chains(&mut self, family: $crate::Family, table: Option<&str>) -> $crate::Result<Vec<$crate::Chain>> {
                $crate::client::$aw!(self.dump(&$crate::proto::Request::chains(family, table)))
            }

            /// Get a chain by name.
            pub $($kw)* fn get_chain(&mut self, family: $crate::Family, table: &str, name: &str) -> $crate::Result<$crate::Chain> {
                $crate::client::$aw!(self.get(&$crate::proto::Request::chain(family, table, name)))
            }

            /// List rules (with their counters), optionally of one table/chain.
            pub $($kw)* fn list_rules(&mut self, family: $crate::Family, table: Option<&str>, chain: Option<&str>) -> $crate::Result<Vec<$crate::Rule>> {
                $crate::client::$aw!(self.dump(&$crate::proto::Request::rules(family, table, chain, false)))
            }

            /// List rules and atomically reset their counters and quotas.
            pub $($kw)* fn list_rules_reset(&mut self, family: $crate::Family, table: Option<&str>, chain: Option<&str>) -> $crate::Result<$crate::ResetDump<$crate::Rule>> {
                let (items, interrupted) = $crate::client::$aw!(self.dump_vec_once(&$crate::proto::Request::rules(family, table, chain, true)))?;
                Ok($crate::ResetDump { items, interrupted })
            }

            /// Get a rule by handle.
            pub $($kw)* fn get_rule(&mut self, family: $crate::Family, table: &str, chain: &str, handle: u64) -> $crate::Result<$crate::Rule> {
                $crate::client::$aw!(self.get(&$crate::proto::Request::rule(family, table, chain, handle, false)))
            }

            /// List sets (including anonymous ones), optionally of one table.
            pub $($kw)* fn list_sets(&mut self, family: $crate::Family, table: Option<&str>) -> $crate::Result<Vec<$crate::Set>> {
                $crate::client::$aw!(self.dump(&$crate::proto::Request::sets(family, table)))
            }

            /// Get a set by name.
            pub $($kw)* fn get_set(&mut self, family: $crate::Family, table: &str, name: &str) -> $crate::Result<$crate::Set> {
                $crate::client::$aw!(self.get(&$crate::proto::Request::set(family, table, name)))
            }

            /// List the elements of a set.
            pub $($kw)* fn list_elems(&mut self, family: $crate::Family, table: &str, set: &str) -> $crate::Result<Vec<$crate::SetElem>> {
                let lists: Vec<$crate::SetElemList> = $crate::client::$aw!(self.dump(&$crate::proto::Request::elems(family, table, set, false)))?;
                Ok(lists.into_iter().flat_map(|l| l.elems).collect())
            }

            /// List the elements of a set and reset their stateful
            /// expressions (counters, quotas). Requires kernel >= 6.5.
            pub $($kw)* fn list_elems_reset(&mut self, family: $crate::Family, table: &str, set: &str) -> $crate::Result<$crate::ResetDump<$crate::SetElem>> {
                let (lists, interrupted): (Vec<$crate::SetElemList>, bool) =
                    $crate::client::$aw!(self.dump_vec_once(&$crate::proto::Request::elems(family, table, set, true)))?;
                let items = lists.into_iter().flat_map(|l| l.elems).collect();
                Ok($crate::ResetDump { items, interrupted })
            }

            /// Look up specific keys in a set. Fails with `ENOENT` if any
            /// key is missing.
            pub $($kw)* fn get_elems(&mut self, family: $crate::Family, table: &str, set: &str, keys: &[$crate::SetElem]) -> $crate::Result<Vec<$crate::SetElem>> {
                // (Not a dump, so never interrupted.)
                let (lists, _): (Vec<$crate::SetElemList>, bool) =
                    $crate::client::$aw!(self.dump_vec_once(&$crate::proto::Request::get_elems(family, table, set, keys, false)))?;
                Ok(lists.into_iter().flat_map(|l| l.elems).collect())
            }

            /// Look up specific keys in a set and reset their stateful
            /// expressions (counters, quotas), returning the values before
            /// the reset. Requires kernel >= 6.5.
            pub $($kw)* fn get_elems_reset(&mut self, family: $crate::Family, table: &str, set: &str, keys: &[$crate::SetElem]) -> $crate::Result<Vec<$crate::SetElem>> {
                let (lists, _): (Vec<$crate::SetElemList>, bool) =
                    $crate::client::$aw!(self.dump_vec_once(&$crate::proto::Request::get_elems(family, table, set, keys, true)))?;
                Ok(lists.into_iter().flat_map(|l| l.elems).collect())
            }

            /// List stateful objects, optionally filtered by table and type.
            pub $($kw)* fn list_objs(&mut self, family: $crate::Family, table: Option<&str>, ty: Option<$crate::ObjType>) -> $crate::Result<Vec<$crate::Obj>> {
                $crate::client::$aw!(self.dump(&$crate::proto::Request::objs(family, table, ty, false)))
            }

            /// List stateful objects and atomically reset counters/quotas.
            pub $($kw)* fn list_objs_reset(&mut self, family: $crate::Family, table: Option<&str>, ty: Option<$crate::ObjType>) -> $crate::Result<$crate::ResetDump<$crate::Obj>> {
                let (items, interrupted) = $crate::client::$aw!(self.dump_vec_once(&$crate::proto::Request::objs(family, table, ty, true)))?;
                Ok($crate::ResetDump { items, interrupted })
            }

            /// Get a stateful object (e.g. read a named counter).
            pub $($kw)* fn get_obj(&mut self, family: $crate::Family, table: &str, name: &str, ty: $crate::ObjType) -> $crate::Result<$crate::Obj> {
                $crate::client::$aw!(self.get(&$crate::proto::Request::obj(family, table, name, ty, false)))
            }

            /// Get a stateful object and atomically reset it.
            pub $($kw)* fn reset_obj(&mut self, family: $crate::Family, table: &str, name: &str, ty: $crate::ObjType) -> $crate::Result<$crate::Obj> {
                $crate::client::$aw!(self.get(&$crate::proto::Request::obj(family, table, name, ty, true)))
            }

            /// List flowtables.
            pub $($kw)* fn list_flowtables(&mut self, family: $crate::Family, table: Option<&str>) -> $crate::Result<Vec<$crate::Flowtable>> {
                $crate::client::$aw!(self.dump(&$crate::proto::Request::flowtables(family, table)))
            }

            /// Take a consistent snapshot of the whole ruleset of a family
            /// ([`Family::Unspec`](crate::Family::Unspec) for all), retrying
            /// if it changes while being read.
            pub $($kw)* fn list_ruleset(&mut self, family: $crate::Family) -> $crate::Result<$crate::Ruleset> {
                for attempt in 0..$crate::client::DUMP_RETRIES {
                    $crate::client::$sleep!(attempt);
                    let genid = $crate::client::$aw!(self.get_gen())?;
                    let mut rs = $crate::Ruleset { genid, ..Default::default() };
                    rs.tables = $crate::client::$aw!(self.list_tables(family))?;
                    rs.chains = $crate::client::$aw!(self.list_chains(family, None))?;
                    rs.objs = $crate::client::$aw!(self.list_objs(family, None, None))?;
                    rs.flowtables = $crate::client::$aw!(self.list_flowtables(family, None))?;
                    let sets = $crate::client::$aw!(self.list_sets(family, None))?;
                    let mut ok = true;
                    for s in sets {
                        match $crate::client::$aw!(self.list_elems(s.family, &s.table, &s.name)) {
                            Ok(e) => rs.sets.push((s, e)),
                            // The set disappeared concurrently: retry.
                            Err(e) if e.is_not_found() => { ok = false; break; }
                            Err(e) => return Err(e),
                        }
                    }
                    if !ok {
                        continue;
                    }
                    rs.rules = $crate::client::$aw!(self.list_rules(family, None, None))?;
                    if $crate::client::$aw!(self.get_gen())? == genid {
                        return Ok(rs);
                    }
                }
                Err($crate::Error::DumpInterrupted)
            }
        }
    };
}
pub(crate) use client_methods;
