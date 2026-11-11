export type DetectedTeamAddress = { ip: string; cidr: string; host: boolean };
export type OnboardingInput = { bindIP: string; publicIP: string; allowedCIDR: string };

// Keep valid user choices; replace addresses and their default subnet together.
export function reconcileOnboardingInput(previous: OnboardingInput, addresses: DetectedTeamAddress[], wsl: boolean, preferDetectedHost = false): OnboardingInput {
  const local = addresses.filter((address) => !address.host);
  const bind = local.find((address) => address.ip === previous.bindIP) ?? local[0];
  const choices = addresses.filter((address) => (wsl && address.host) || address.ip === bind?.ip);
  const published = (preferDetectedHost ? choices.find((address) => address.host) : undefined)
    ?? choices.find((address) => address.ip === previous.publicIP)
    ?? choices.find((address) => address.host) ?? bind;
  return {
    bindIP: bind?.ip ?? "",
    publicIP: published?.ip ?? "",
    allowedCIDR: published && published.ip === previous.publicIP && previous.allowedCIDR
      ? previous.allowedCIDR : published?.cidr ?? "",
  };
}
