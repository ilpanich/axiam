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

  // ds-raw:__ds_raw__
  var require_ds_raw = __commonJS({
    "ds-raw:__ds_raw__"(exports, module) {
      init_define_import_meta_env();
      module.exports = window.AxiamUI;
    }
  });

  // .design-sync/previews/Toaster.tsx
  var Toaster_exports = {};
  __export(Toaster_exports, {
    DefaultToast: () => DefaultToast,
    DestructiveToast: () => DestructiveToast,
    StackedToasts: () => StackedToasts
  });
  init_define_import_meta_env();
  var import_react = __toESM(require_react_shim(), 1);

  // ds-shim:ds
  var ds_exports = {};
  __export(ds_exports, {
    default: () => ds_default
  });
  init_define_import_meta_env();
  __reExport(ds_exports, __toESM(require_ds_raw()));
  var g = window.AxiamUI;
  var ds_default = "default" in g ? g.default : g;

  // .design-sync/previews/Toaster.tsx
  var import_jsx_runtime = __toESM(require_react_shim(), 1);
  function Stage({ children }) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      "div",
      {
        style: {
          position: "relative",
          transform: "translateZ(0)",
          height: 240,
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
  function Seed({ toasts }) {
    const { toast } = (0, ds_exports.useToast)();
    (0, import_react.useEffect)(() => {
      toasts.forEach((t) => toast({ duration: 6e5, ...t }));
    }, []);
    return null;
  }
  function ToastHost({ toasts }) {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Stage, { children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Toaster, {}),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Seed, { toasts })
    ] });
  }
  function DefaultToast() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ToastHost,
      {
        toasts: [{ description: "Role tenant-admin updated — 4 permissions added." }]
      }
    );
  }
  function DestructiveToast() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ToastHost,
      {
        toasts: [
          {
            description: "Failed to revoke certificate 3f:a9:1c — the organization CA is offline.",
            variant: "destructive"
          }
        ]
      }
    );
  }
  function StackedToasts() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(
      ToastHost,
      {
        toasts: [
          { description: "Webhook cert-events re-delivered to 2 endpoints." },
          { description: "MFA enforcement is now required for tenant acme-prod." },
          {
            description: "Service account ci-deploy-bot could not be deleted.",
            variant: "destructive"
          }
        ]
      }
    );
  }
  return __toCommonJS(Toaster_exports);
})();
