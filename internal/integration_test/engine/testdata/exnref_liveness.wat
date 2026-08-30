;; Two exceptions are live at once: A is caught by reference and parked in a
;; local (or a global), B is thrown and caught while A is still held, then A
;; is rethrown and its param read back. Nothing in Go references A between the
;; catch and the rethrow, so an engine that roots only the most recent
;; exception lets A be collected. See wazero/wazero#2522.
(module
  ;; churn asks the host to collect and then overwrite freed memory.
  (import "env" "churn" (func $churn))

  (tag $a (param i32))
  (tag $b)
  (global $ge (mut exnref) (ref.null exn))

  ;; throw_b overwrites the engine's most-recent-exception slot with B.
  (func $throw_b
    (block $h
      (try_table (catch $b $h) (throw $b))))

  ;; rethrow raises x again and reads the i32 it carries.
  (func $rethrow (param $x exnref) (result i32)
    (block $h (result i32)
      (try_table (catch $a $h) (throw_ref (local.get $x)))
      (unreachable)))

  (func (export "exnref_local") (result i32)
    (local $x exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 13)))
      (unreachable))
    (local.set $x)
    (call $throw_b)
    (call $churn)
    (call $rethrow (local.get $x)))

  (func (export "exnref_global") (result i32)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 14)))
      (unreachable))
    (global.set $ge)
    (call $throw_b)
    (call $churn)
    (call $rethrow (global.get $ge)))
)
