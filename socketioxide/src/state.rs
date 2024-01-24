//! An optional global state for the server which is backed by a [`TypeMap`].
//! The state is global and not part of the socketio instance because it is impossible
//! to have extractors with lifetimes. Therefore the only way to propagate a `State` reference
//! to a handler parameter is to make is `'static`.
use state::TypeMap;
static mut STATE: TypeMap![Send + Sync] = <TypeMap![Send + Sync]>::new();

// SAFETY: even if the state is mut and therefeore not thread safe,
// each of the following functions are called disctincly in different
// step of the server lifecycle.

// SAFETY: the `get_state` is called many times from extractors but never mutably and after the `freeze_state` call
pub(crate) fn get_state<T: Send + Sync + 'static>() -> Option<&'static T> {
    unsafe { STATE.try_get::<T>() }
}
// SAFETY: the `freeze_state` is only called once at the launch of the server
pub(crate) fn freeze_state() {
    unsafe { STATE.freeze() }
}
// SAFETY: the `set_state` is only called when building the server and can be called multiple times
pub(crate) fn set_state<T: Send + Sync + 'static>(value: T) {
    unsafe { STATE.set(value) };
}

mod test {
    #[test]
    fn state_lifecycle() {
        use super::TypeMap;
        // Mimic the parent static state
        static mut STATE: TypeMap![Send + Sync] = <TypeMap![Send + Sync]>::new();

        unsafe { STATE.set(1i32) };
        unsafe { STATE.set("hello") };

        assert_eq!(unsafe { STATE.len() }, 2);
        unsafe { STATE.freeze() }

        assert_eq!(unsafe { STATE.try_get::<i32>() }, Some(&1));
        assert_eq!(unsafe { STATE.try_get::<&str>() }, Some(&"hello"));
    }
}
