import assert from "node:assert/strict";
import test from "node:test";
import { reconcileOnboardingInput } from "./team-onboarding-input";

const local = { ip: "172.20.1.2", cidr: "172.20.0.0/20", host: false };
const host = { ip: "192.168.2.3", cidr: "192.168.2.0/24", host: true };
test("network change replaces a vanished public address and its stale subnet together", () => {
  assert.deepEqual(reconcileOnboardingInput({bindIP:local.ip,publicIP:"10.1.2.3",allowedCIDR:"10.1.2.0/24"},[local,host],true),
    {bindIP:local.ip,publicIP:host.ip,allowedCIDR:host.cidr});
});
test("refresh preserves a valid host choice and a manually restricted subnet", () => {
  const previous = {bindIP:local.ip,publicIP:host.ip,allowedCIDR:host.ip+"/32"};
  assert.deepEqual(reconcileOnboardingInput(previous,[host,local],true),previous);
});
test("disconnected interfaces clear unusable selections", () => {
  assert.deepEqual(reconcileOnboardingInput({bindIP:local.ip,publicIP:host.ip,allowedCIDR:host.cidr},[],true),
    {bindIP:"",publicIP:"",allowedCIDR:""});
});
test("recovered Windows detection replaces an automatic WSL-only public default", () => {
  assert.deepEqual(reconcileOnboardingInput({bindIP:local.ip,publicIP:local.ip,allowedCIDR:local.cidr},[local,host],true,true),
    {bindIP:local.ip,publicIP:host.ip,allowedCIDR:host.cidr});
});
