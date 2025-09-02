import { Bytes, Struct, UInt32, Provable } from 'o1js';

export class Bytes32 extends Bytes(32) {}

export class FinalRoundInputs extends Struct({
  state: Provable.Array(UInt32, 8), // 256 bits = 8 * 32 bits
  initialState: Provable.Array(UInt32, 8),
  messageWord: UInt32,
  roundConstant: UInt32,
}) {}