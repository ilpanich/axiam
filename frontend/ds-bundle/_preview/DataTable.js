var __dsPreview = (() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __esm = (fn, res, err) => function __init() {
    if (err) throw err[0];
    try {
      return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
    } catch (e) {
      throw err = [e], e;
    }
  };
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // <define:import.meta.env>
  var init_define_import_meta_env = __esm({
    "<define:import.meta.env>"() {
    }
  });

  // ds-raw:__ds_raw__
  var require_ds_raw = __commonJS({
    "ds-raw:__ds_raw__"(exports, module) {
      init_define_import_meta_env();
      module.exports = window.AxiamUI;
    }
  });

  // shim:react-shim
  var require_react_shim = __commonJS({
    "shim:react-shim"(exports, module) {
      init_define_import_meta_env();
      var R = window.React;
      function np(p, k) {
        var o = {};
        for (var x in p) if (x !== "children") o[x] = p[x];
        if (k !== void 0) o.key = k;
        return o;
      }
      function jsx2(t, p, k) {
        var c = p && p.children;
        return c === void 0 ? R.createElement(t, np(p, k)) : R.createElement(t, np(p, k), c);
      }
      function jsxs(t, p, k) {
        return R.createElement.apply(R, [t, np(p, k)].concat(p.children));
      }
      module.exports = R;
      module.exports.jsx = jsx2;
      module.exports.jsxs = jsxs;
      module.exports.jsxDEV = function(t, p, k, s) {
        return (s ? jsxs : jsx2)(t, p, k);
      };
      module.exports.Fragment = R.Fragment;
    }
  });

  // .design-sync/previews/DataTable.tsx
  var DataTable_exports = {};
  __export(DataTable_exports, {
    Certificates: () => Certificates,
    Empty: () => Empty,
    Loading: () => Loading,
    Users: () => Users
  });
  init_define_import_meta_env();

  // ds-shim:ds
  var ds_exports = {};
  __export(ds_exports, {
    default: () => ds_default
  });
  init_define_import_meta_env();
  __reExport(ds_exports, __toESM(require_ds_raw()));
  var g = window.AxiamUI;
  var ds_default = "default" in g ? g.default : g;

  // .design-sync/previews/DataTable.tsx
  var import_jsx_runtime = __toESM(require_react_shim(), 1);
  var userColumns = [
    { key: "email", header: "User" },
    {
      key: "roles",
      header: "Roles",
      render: (row) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", { className: "flex flex-wrap gap-1", children: row.roles.map((r) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Badge, { variant: "outline", children: r }, r)) })
    },
    {
      key: "mfa",
      header: "MFA",
      render: (row) => row.mfa ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Badge, { variant: "accent", children: "TOTP" }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "text-muted-foreground", children: "—" })
    },
    {
      key: "status",
      header: "Status",
      render: (row) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.StatusBadge, { status: row.status })
    },
    { key: "last_login", header: "Last login" }
  ];
  var users = [
    {
      id: "u-1",
      email: "elena.rossi@acme.io",
      roles: ["tenant:admin"],
      mfa: true,
      status: "active",
      last_login: "2026-07-11 08:42 UTC"
    },
    {
      id: "u-2",
      email: "marcus.hale@acme.io",
      roles: ["users:read", "audit:export"],
      mfa: true,
      status: "active",
      last_login: "2026-07-10 21:07 UTC"
    },
    {
      id: "u-3",
      email: "svc-billing@acme.io",
      roles: ["service-account"],
      mfa: false,
      status: "active",
      last_login: "2026-07-11 09:15 UTC"
    },
    {
      id: "u-4",
      email: "priya.nair@acme.io",
      roles: ["certificates:issue"],
      mfa: false,
      status: "inactive",
      last_login: "2026-05-29 13:31 UTC"
    },
    {
      id: "u-5",
      email: "d.okafor@acme.io",
      roles: ["users:write"],
      mfa: true,
      status: "revoked",
      last_login: "2026-06-02 17:58 UTC"
    }
  ];
  var certColumns = [
    { key: "subject", header: "Subject" },
    { key: "algorithm", header: "Algorithm" },
    {
      key: "serial",
      header: "Serial",
      render: (row) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "font-mono text-xs text-foreground/70", children: row.serial })
    },
    { key: "expires", header: "Expires" },
    {
      key: "status",
      header: "Status",
      render: (row) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.StatusBadge, { status: row.status })
    }
  ];
  var certificates = [
    {
      id: "c-1",
      subject: "CN=gateway.acme-prod, OU=edge",
      algorithm: "Ed25519",
      serial: "3f:a9:1c:04:8b:e2",
      expires: "2027-03-14",
      status: "active"
    },
    {
      id: "c-2",
      subject: "CN=iot-sensor-0412, OU=devices",
      algorithm: "RSA-4096",
      serial: "7b:22:de:90:31:af",
      expires: "2026-11-02",
      status: "active"
    },
    {
      id: "c-3",
      subject: "CN=svc-billing, OU=services",
      algorithm: "Ed25519",
      serial: "aa:14:6c:75:0d:19",
      expires: "2026-08-30",
      status: "active"
    },
    {
      id: "c-4",
      subject: "CN=iot-sensor-0177, OU=devices",
      algorithm: "RSA-4096",
      serial: "c1:8e:33:b0:47:5d",
      expires: "2026-04-11",
      status: "revoked"
    }
  ];
  var Users = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.DataTable, { columns: userColumns, data: users, getRowKey: (r) => r.id });
  var Certificates = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
    ds_exports.DataTable,
    {
      columns: certColumns,
      data: certificates,
      getRowKey: (r) => r.id
    }
  );
  var Loading = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.DataTable, { columns: userColumns, data: [], isLoading: true });
  var Empty = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
    ds_exports.DataTable,
    {
      columns: certColumns,
      data: [],
      emptyMessage: "No certificates issued for this tenant yet."
    }
  );
  return __toCommonJS(DataTable_exports);
})();
