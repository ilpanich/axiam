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

  // .design-sync/previews/FormDialog.tsx
  var FormDialog_exports = {};
  __export(FormDialog_exports, {
    CreateServiceAccount: () => CreateServiceAccount,
    RegisterOAuthClient: () => RegisterOAuthClient,
    Submitting: () => Submitting
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

  // .design-sync/previews/FormDialog.tsx
  var import_jsx_runtime = __toESM(require_react_shim(), 1);
  function Stage({ children }) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      "div",
      {
        style: {
          position: "relative",
          transform: "translateZ(0)",
          height: 480,
          width: "100%",
          overflow: "hidden",
          borderRadius: 12,
          border: "1px solid rgba(255,255,255,0.08)",
          background: "linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%)"
        },
        children
      }
    );
  }
  var noop = () => {
  };
  var submit = (e) => e.preventDefault();
  var CreateServiceAccount = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stage, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(
    ds_exports.FormDialog,
    {
      open: true,
      onClose: noop,
      onSubmit: submit,
      title: "New service account",
      submitLabel: "Create account",
      children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "sa-name", children: "Name" }),
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "sa-name", defaultValue: "svc-billing" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "sa-desc", children: "Description" }),
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
            ds_exports.Textarea,
            {
              id: "sa-desc",
              rows: 3,
              defaultValue: "Machine-to-machine client for the invoicing pipeline."
            }
          )
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
          ds_exports.ToggleField,
          {
            id: "sa-mtls",
            label: "Require mTLS client certificate",
            checked: true,
            onChange: noop
          }
        )
      ]
    }
  ) });
  var RegisterOAuthClient = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stage, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(
    ds_exports.FormDialog,
    {
      open: true,
      onClose: noop,
      onSubmit: submit,
      title: "Register OAuth2 client",
      submitLabel: "Register",
      children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "oc-name", children: "Client name" }),
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "oc-name", defaultValue: "acme-portal" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "oc-redirect", children: "Redirect URI" }),
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
            ds_exports.Input,
            {
              id: "oc-redirect",
              defaultValue: "https://portal.acme.io/oauth2/callback"
            }
          )
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
          ds_exports.ToggleField,
          {
            id: "oc-pkce",
            label: "Enforce PKCE (Authorization Code)",
            checked: true,
            onChange: noop
          }
        ),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
          ds_exports.ToggleField,
          {
            id: "oc-refresh",
            label: "Issue rotating refresh tokens",
            checked: false,
            onChange: noop
          }
        )
      ]
    }
  ) });
  var Submitting = () => /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stage, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(
    ds_exports.FormDialog,
    {
      open: true,
      onClose: noop,
      onSubmit: submit,
      title: "Issue X.509 certificate",
      submitLabel: "Issue certificate",
      isLoading: true,
      children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "cert-cn", children: "Common name" }),
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "cert-cn", defaultValue: "gateway.acme-prod" })
        ] }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { className: "space-y-2", children: [
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Label, { htmlFor: "cert-alg", children: "Algorithm" }),
          /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Input, { id: "cert-alg", defaultValue: "Ed25519" })
        ] })
      ]
    }
  ) });
  return __toCommonJS(FormDialog_exports);
})();
