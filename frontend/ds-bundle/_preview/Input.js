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

  // .design-sync/previews/Input.tsx
  var Input_exports = {};
  __export(Input_exports, {
    Default: () => Default,
    Disabled: () => Disabled,
    Invalid: () => Invalid,
    Placeholder: () => Placeholder,
    Types: () => Types
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

  // .design-sync/previews/Input.tsx
  var import_jsx_runtime = __toESM(require_react_shim(), 1);
  var field = { maxWidth: 340 };
  var Default = () => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", style: field, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "tenant-slug", children: "Tenant slug" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "tenant-slug", defaultValue: "acme-production" })
  ] });
  var Types = () => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-4", style: field, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "user-email", children: "Email" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "user-email", type: "email", defaultValue: "dana.okonkwo@acme.io" })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "user-password", children: "Password" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "user-password", type: "password", defaultValue: "correct-horse-battery" })
    ] }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "totp-code", children: "TOTP code" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "totp-code", inputMode: "numeric", defaultValue: "418 902" })
    ] })
  ] });
  var Placeholder = () => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", style: field, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "redirect-uri", children: "OAuth2 redirect URI" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "redirect-uri", placeholder: "https://app.acme.io/oauth2/callback" })
  ] });
  var Disabled = () => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", style: field, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "client-id", children: "Client ID" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "client-id", disabled: true, defaultValue: "cl_9f3a7c21-4e0b-4a6d-9b21-7f0c2d8e1a55" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { className: "text-xs text-muted-foreground", children: "Generated at creation and immutable." })
  ] });
  var Invalid = () => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", style: field, children: [
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "webhook-url", children: "Webhook endpoint" }),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ds_exports.Input,
      {
        id: "webhook-url",
        "aria-invalid": true,
        className: "border-destructive",
        defaultValue: "http://hooks.acme.io/axiam"
      }
    ),
    /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { className: "text-xs text-destructive", children: "Endpoint must use TLS (https://)." })
  ] });
  return __toCommonJS(Input_exports);
})();
