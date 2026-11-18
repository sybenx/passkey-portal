// Portals this one trusts as backups, both ways: it offers copies only to these, and accepts copies
// only from these. Each must list this portal back. Origins only, e.g. 'https://portal2.example'.
// An empty list hides "Add a backup portal". Edited by whoever runs the portal.
//
// It is a module, not mirrors.json, because the pages' CSP (connect-src 'none') blocks loading JSON.
export default [];
