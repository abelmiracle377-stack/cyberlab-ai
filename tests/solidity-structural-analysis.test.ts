import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeSoliditySource } from "../lib/solidity-static-analysis";

function ids(source: string): string[] {
  return analyzeSoliditySource(source).findings.map((f) => f.id);
}

test("flags unprotected selfdestruct but not a guarded one", () => {
  const vulnerable = `pragma solidity ^0.8.20;
contract Kill {
  function boom() external { selfdestruct(payable(msg.sender)); }
}`;
  assert.ok(ids(vulnerable).includes("SOL-ACL-001"));

  const guarded = `pragma solidity ^0.8.20;
contract Kill {
  address owner;
  modifier onlyOwner() { require(msg.sender == owner); _; }
  function boom() external onlyOwner { selfdestruct(payable(owner)); }
}`;
  assert.ok(!ids(guarded).includes("SOL-ACL-001"));
});

test("flags unprotected delegatecall", () => {
  const vulnerable = `pragma solidity ^0.8.20;
contract Proxy {
  function forward(address impl, bytes calldata data) external {
    impl.delegatecall(data);
  }
}`;
  assert.ok(ids(vulnerable).includes("SOL-ACL-002"));

  const guarded = `pragma solidity ^0.8.20;
contract Proxy {
  function forward(address impl, bytes calldata data) external onlyAdmin {
    impl.delegatecall(data);
  }
}`;
  assert.ok(!ids(guarded).includes("SOL-ACL-002"));
});

test("flags ownership takeover without access control", () => {
  const vulnerable = `pragma solidity ^0.8.20;
contract Owned {
  address owner;
  function setOwner(address next) public { owner = next; }
}`;
  assert.ok(ids(vulnerable).includes("SOL-ACL-003"));

  const guarded = `pragma solidity ^0.8.20;
contract Owned {
  address owner;
  function setOwner(address next) public {
    require(msg.sender == owner, "not owner");
    owner = next;
  }
}`;
  assert.ok(!ids(guarded).includes("SOL-ACL-003"));
});

test("flags external-call-before-state-update reentrancy", () => {
  const vulnerable = `pragma solidity ^0.8.20;
contract Bank {
  mapping(address => uint) balances;
  function withdraw(uint amount) external {
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount;
  }
}`;
  assert.ok(ids(vulnerable).includes("SOL-REENT-001"));
});

test("does not flag checks-effects-interactions order", () => {
  const safe = `pragma solidity ^0.8.20;
contract Bank {
  mapping(address => uint) balances;
  function withdraw(uint amount) external {
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
  }
}`;
  assert.ok(!ids(safe).includes("SOL-REENT-001"));
});

test("internal functions are not treated as externally exposed", () => {
  const internal = `pragma solidity ^0.8.20;
contract C {
  function _destroy() internal { selfdestruct(payable(msg.sender)); }
}`;
  assert.ok(!ids(internal).includes("SOL-ACL-001"));
});

test("a benign view function produces no structural findings", () => {
  const safe = `pragma solidity ^0.8.20;
contract C {
  uint total;
  function get() external view returns (uint) { return total; }
}`;
  const found = ids(safe).filter((id) => id.startsWith("SOL-ACL") || id.startsWith("SOL-REENT"));
  assert.deepEqual(found, []);
});

test("comments cannot trigger structural findings", () => {
  const safe = `pragma solidity ^0.8.20;
contract C {
  // function evil() external { selfdestruct(payable(msg.sender)); }
  function ok() external pure returns (uint) { return 1; }
}`;
  assert.ok(!ids(safe).includes("SOL-ACL-001"));
});

test("flags constructor deployment arguments", () => {
  const c = `pragma solidity ^0.8.20;
contract Token {
  address owner;
  constructor(address initialOwner, uint256 cap) { owner = initialOwner; }
}`;
  assert.ok(ids(c).includes("SOL-DEPLOY-001"));
});

test("no constructor-arg finding when constructor takes none", () => {
  const c = `pragma solidity ^0.8.20;
contract Token { constructor() {} }`;
  assert.ok(!ids(c).includes("SOL-DEPLOY-001"));
});

test("flags library that needs link-time address", () => {
  const c = `pragma solidity ^0.8.20;
library MathLib { function add(uint a, uint b) public pure returns (uint) { return a + b; } }
contract C { using MathLib for uint; }`;
  assert.ok(ids(c).includes("SOL-DEPLOY-002"));
});

test("flags upgradeable contract needing initialisation", () => {
  const c = `pragma solidity ^0.8.20;
contract C is Initializable {
  function initialize(address owner_) public initializer { }
}`;
  assert.ok(ids(c).includes("SOL-DEPLOY-003"));
});
