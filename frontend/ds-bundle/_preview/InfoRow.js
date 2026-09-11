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
      function jsxs2(t, p, k) {
        return R.createElement.apply(R, [t, np(p, k)].concat(p.children));
      }
      module.exports = R;
      module.exports.jsx = jsx2;
      module.exports.jsxs = jsxs2;
      module.exports.jsxDEV = function(t, p, k, s) {
        return (s ? jsxs2 : jsx2)(t, p, k);
      };
      module.exports.Fragment = R.Fragment;
    }
  });

  // .design-sync/previews/InfoRow.tsx
  var InfoRow_exports = {};
  __export(InfoRow_exports, {
    InDetailPanel: () => InDetailPanel,
    LongWrappingValue: () => LongWrappingValue,
    RichValues: () => RichValues
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

  // .design-sync/previews/InfoRow.tsx
  var import_jsx_runtime = __toESM(require_react_shim(), 1);
  var InDetailPanel = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.SectionCard, { title: "Service account", children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Client ID", children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "font-mono text-xs", children: "svc-billing-sync" }) }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Tenant", children: "Northwind Industrial / production" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Grant type", children: "client_credentials" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Status", children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.StatusBadge, { status: "active" }) }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Last used", children: "2026-07-10 18:42 UTC" })
  ] }) });
  var RichValues = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.SectionCard, { title: "X.509 certificate", children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Subject", children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "font-mono text-xs", children: "CN=iot-gateway-04.axiam.dev" }) }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Serial", children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "font-mono text-xs", children: "3A:7F:19:C4:0B:E2:56:81" }) }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Algorithm", children: "Ed25519" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Permissions", children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.ActionBadge, { action: "read" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.ActionBadge, { action: "write" })
    ] }) }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Not after", children: "2027-03-14 00:00 UTC" })
  ] }) });
  var LongWrappingValue = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.SectionCard, { title: "Webhook endpoint", children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Target URL", children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "break-all font-mono text-xs", children: "https://hooks.northwind-industrial.example/axiam/v1/events?tenant=production" }) }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Events", children: "user.created, user.deleted, role.assigned, certificate.revoked, mfa.enrolled" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.InfoRow, { label: "Signature", children: "HMAC-SHA256" })
  ] }) });
  return __toCommonJS(InfoRow_exports);
})();
