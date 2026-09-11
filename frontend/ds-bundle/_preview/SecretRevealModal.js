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

  // .design-sync/previews/SecretRevealModal.tsx
  var SecretRevealModal_exports = {};
  __export(SecretRevealModal_exports, {
    CertificatePrivateKey: () => CertificatePrivateKey,
    OAuth2ClientCredentials: () => OAuth2ClientCredentials,
    ServiceAccountKey: () => ServiceAccountKey
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

  // .design-sync/previews/SecretRevealModal.tsx
  var import_jsx_runtime = __toESM(require_react_shim(), 1);
  function Stage({ children, height = 520 }) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      "div",
      {
        style: {
          position: "relative",
          transform: "translateZ(0)",
          height,
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
  function OAuth2ClientCredentials() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stage, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ds_exports.SecretRevealModal,
      {
        open: true,
        onClose: noop,
        title: "OAuth2 client registered",
        description: "acme-portal — Authorization Code + PKCE, confidential client.",
        secrets: [
          { label: "Client ID", value: "cl_7f3a91c04b2e4d18a6e0d5c9b1f2a730" },
          {
            label: "Client secret",
            value: "cs_live_9Qk2pR7vNxT4mZbW8sYcJ1hLdE6uA3fGoP0iVrXn"
          }
        ]
      }
    ) });
  }
  function ServiceAccountKey() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stage, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ds_exports.SecretRevealModal,
      {
        open: true,
        onClose: noop,
        title: "Service account key issued",
        description: "ci-deploy-bot — tenant acme-prod. Store this in your pipeline's secret manager.",
        secrets: [
          { label: "Key ID", value: "sak_01J8ZQ4C7N9M2XB5RTKD3PWVH6" },
          {
            label: "Secret key",
            value: "axm_sk_prod_4hT9dLpQ2vRz7XwK1nYcB8mJfS3gU6eA0iOtZrVyNqMxCbDl"
          },
          { label: "Expires", value: "2027-01-14 09:32 UTC (180 days)", mono: false }
        ]
      }
    ) });
  }
  function CertificatePrivateKey() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Stage, { height: 600, children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ds_exports.SecretRevealModal,
      {
        open: true,
        onClose: noop,
        title: "Device certificate issued",
        description: "iot-gateway-04.acme-prod — Ed25519, signed by the acme organization CA. The private key is never stored by AXIAM.",
        secrets: [
          {
            label: "SHA-256 fingerprint",
            value: "3f:a9:1c:7e:04:b2:88:d5:6a:11:c3:9e:0f:47:bd:52"
          },
          {
            label: "Private key (PKCS#8, PEM)",
            value: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIL9kM2xQ0v7ZpR3nHsWc6Ub1TfKdA8yEjXmNoPqRsTuV\n-----END PRIVATE KEY-----"
          }
        ]
      }
    ) });
  }
  return __toCommonJS(SecretRevealModal_exports);
})();
