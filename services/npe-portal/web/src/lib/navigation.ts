// Role-tailored navigation matrix (NPE portal requirements §3). Each portal certificate
// resolves to exactly one NPE role, so navigation is selected by primary role.

import { primaryRole, type UserInfo } from "@/lib/auth";

export interface NavLink {
  text: string;
  href: string;
}

export interface NavGroup {
  text: string;
  items: NavLink[];
}

const CERT_MGMT_SPONSOR: NavLink[] = [
  { text: "Submit Certificate Application", href: "/certificates/apply" },
  { text: "Submit Certificate Rekey", href: "/certificates/rekey" },
  { text: "View Certificate Application Status", href: "/certificates/status" },
  { text: "View My Certificate Applications", href: "/certificates/mine" },
  { text: "View Expiring Certificates", href: "/certificates/expiring" },
  { text: "View Bulk Status", href: "/certificates/bulk-status" },
  { text: "View Certificate Authorities Details", href: "/certificates/ca-details" },
];

const PASSWORD_MGMT: NavLink[] = [
  { text: "Generate Single-Use Token", href: "/passwords/single-use" },
  { text: "Generate Multi-Use Token", href: "/passwords/multi-use" },
];

const SEARCH: NavGroup = {
  text: "Search",
  items: [{ text: "Search", href: "/search" }],
};

export function navGroupsForUser(user: UserInfo | null): NavGroup[] {
  const role = primaryRole(user);

  switch (role) {
    case "pki_sponsor":
      return [
        { text: "Certificate Management", items: CERT_MGMT_SPONSOR },
        { text: "Password Management", items: PASSWORD_MGMT },
        SEARCH,
      ];

    case "pki_sponsor_admin":
      return [
        {
          text: "Certificate Management",
          items: [
            ...CERT_MGMT_SPONSOR,
            { text: "Submit Bulk", href: "/certificates/bulk" },
          ],
        },
        { text: "Password Management", items: PASSWORD_MGMT },
        SEARCH,
      ];

    case "registration_authority":
      return [
        {
          text: "Certificate Management",
          items: [
            ...CERT_MGMT_SPONSOR,
            { text: "Submit Bulk", href: "/certificates/bulk" },
            { text: "Manage Certificate Applications", href: "/ra/applications" },
            { text: "Revoke Certificates", href: "/ra/revoke" },
          ],
        },
        SEARCH,
      ];

    case "caa_admin":
      return [
        {
          text: "User Management",
          items: [{ text: "Manage Users & Roles", href: "/caa/users" }],
        },
        {
          text: "Wildcard Management",
          items: [{ text: "Namespaces & Wildcards", href: "/caa/namespaces" }],
        },
        {
          text: "System Configuration",
          items: [{ text: "System Configuration", href: "/caa/config" }],
        },
        SEARCH,
      ];

    default:
      return [];
  }
}

/** Flat list of all valid hrefs for the user (route guard helper). */
export function allowedHrefs(user: UserInfo | null): Set<string> {
  return new Set(navGroupsForUser(user).flatMap((g) => g.items.map((i) => i.href)));
}
