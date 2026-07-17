use serde::Serialize;
use smali::android::binary_xml::{AndroidManifest, ManifestElement, ManifestValue};

fn attr_str(element: &ManifestElement, name: &str) -> Option<String> {
    element.attribute_value(name).map(|v| match v {
        ManifestValue::String(s) => s.clone(),
        ManifestValue::Boolean(b) => b.to_string(),
        ManifestValue::Integer(i) => i.to_string(),
        ManifestValue::Hex(h) => format!("0x{:x}", h),
        ManifestValue::Reference(r) => format!("@0x{:08x}", r),
    })
}

fn attr_bool(element: &ManifestElement, name: &str) -> Option<bool> {
    element.attribute_value(name).and_then(|v| match v {
        ManifestValue::Boolean(b) => Some(*b),
        ManifestValue::Integer(i) => Some(*i != 0),
        ManifestValue::String(s) => match s.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn children_by_tag<'a>(
    element: &'a ManifestElement,
    tag: &'a str,
) -> impl Iterator<Item = &'a ManifestElement> + 'a {
    element.children.iter().filter(move |c| c.tag == tag)
}

fn first_child_by_tag<'a>(
    element: &'a ManifestElement,
    tag: &str,
) -> Option<&'a ManifestElement> {
    element.children.iter().find(|c| c.tag == tag)
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestSummary {
    pub package_name: Option<String>,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub install_location: Option<String>,
    pub platform_build_version_code: Option<String>,
    pub platform_build_version_name: Option<String>,
    pub sdk: SdkInfo,
    pub uses_permissions: Vec<String>,
    pub declares_permissions: Vec<PermissionDecl>,
    pub uses_features: Vec<FeatureInfo>,
    pub main_activity: Option<String>,
    pub application: Option<ApplicationSummary>,
    pub instrumentation: Vec<InstrumentationInfo>,
    pub supports_screens: Option<SupportsScreensInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SdkInfo {
    pub min_sdk_version: Option<String>,
    pub target_sdk_version: Option<String>,
    pub max_sdk_version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PermissionDecl {
    pub name: String,
    pub protection_level: Option<String>,
    pub label: Option<String>,
    pub description: Option<String>,
    pub permission_group: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FeatureInfo {
    pub name: Option<String>,
    pub gl_es_version: Option<String>,
    pub required: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ApplicationSummary {
    pub label: Option<String>,
    pub icon: Option<String>,
    pub name: Option<String>,
    pub allow_backup: Option<bool>,
    pub debuggable: Option<bool>,
    pub test_only: Option<bool>,
    pub has_code: Option<bool>,
    pub theme: Option<String>,
    pub allow_clear_user_data: Option<bool>,
    pub hardware_accelerated: Option<bool>,
    pub large_heap: Option<bool>,
    pub supports_rtl: Option<bool>,
    pub activities: Vec<ComponentInfo>,
    pub services: Vec<ComponentInfo>,
    pub receivers: Vec<ComponentInfo>,
    pub providers: Vec<ProviderInfo>,
    pub uses_libraries: Vec<LibraryInfo>,
    pub meta_data: Vec<MetaDataInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ComponentInfo {
    pub name: String,
    pub exported: Option<bool>,
    pub enabled: Option<bool>,
    pub permission: Option<String>,
    pub process: Option<String>,
    pub intent_filters: Vec<IntentFilterInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_changes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_activity_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screen_orientation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_input_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_soft_input_mode: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderInfo {
    pub name: String,
    pub authorities: Option<String>,
    pub exported: Option<bool>,
    pub enabled: Option<bool>,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
    pub permission: Option<String>,
    pub grant_uri_permissions: Option<bool>,
    pub multiprocess: Option<bool>,
    pub syncable: Option<bool>,
    pub intent_filters: Vec<IntentFilterInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IntentFilterInfo {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<DataInfo>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DataInfo {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub path_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LibraryInfo {
    pub name: String,
    pub required: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MetaDataInfo {
    pub name: String,
    pub value: Option<String>,
    pub resource: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct InstrumentationInfo {
    pub name: String,
    pub target_package: Option<String>,
    pub label: Option<String>,
    pub handle_profiling: Option<bool>,
    pub functional_test: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SupportsScreensInfo {
    pub resizeable: Option<bool>,
    pub small_screens: Option<bool>,
    pub normal_screens: Option<bool>,
    pub large_screens: Option<bool>,
    pub xlarge_screens: Option<bool>,
    pub any_density: Option<bool>,
    pub requires_smallest_width_dp: Option<String>,
    pub compatible_width_limit_dp: Option<String>,
    pub largest_width_limit_dp: Option<String>,
}

fn extract_component(
    element: &ManifestElement,
) -> ComponentInfo {
    let intent_filters: Vec<IntentFilterInfo> = children_by_tag(element, "intent-filter")
        .map(|intent_filter| {
            let actions: Vec<String> = children_by_tag(intent_filter, "action")
                .filter_map(|a| attr_str(a, "android:name"))
                .collect();
            let categories: Vec<String> = children_by_tag(intent_filter, "category")
                .filter_map(|c| attr_str(c, "android:name"))
                .collect();
            let data: Vec<DataInfo> = children_by_tag(intent_filter, "data")
                .map(|d| DataInfo {
                    scheme: attr_str(d, "android:scheme"),
                    host: attr_str(d, "android:host"),
                    port: attr_str(d, "android:port"),
                    path: attr_str(d, "android:path"),
                    path_pattern: attr_str(d, "android:pathPattern"),
                    path_prefix: attr_str(d, "android:pathPrefix"),
                    mime_type: attr_str(d, "android:mimeType"),
                })
                .collect();
            IntentFilterInfo {
                actions,
                categories,
                data,
            }
        })
        .collect();

    ComponentInfo {
        name: attr_str(element, "android:name").unwrap_or_default(),
        exported: attr_bool(element, "android:exported"),
        enabled: attr_bool(element, "android:enabled"),
        permission: attr_str(element, "android:permission"),
        process: attr_str(element, "android:process"),
        intent_filters,
        launch_mode: attr_str(element, "android:launchMode"),
        orientation: attr_str(element, "android:screenOrientation"),
        config_changes: attr_str(element, "android:configChanges"),
        parent_activity_name: attr_str(element, "android:parentActivityName"),
        screen_orientation: attr_str(element, "android:screenOrientation"),
        soft_input_mode: attr_str(element, "android:windowSoftInputMode"),
        window_soft_input_mode: attr_str(element, "android:windowSoftInputMode"),
    }
}

fn extract_provider(element: &ManifestElement) -> ProviderInfo {
    let intent_filters: Vec<IntentFilterInfo> = children_by_tag(element, "intent-filter")
        .map(|intent_filter| {
            let actions: Vec<String> = children_by_tag(intent_filter, "action")
                .filter_map(|a| attr_str(a, "android:name"))
                .collect();
            let categories: Vec<String> = children_by_tag(intent_filter, "category")
                .filter_map(|c| attr_str(c, "android:name"))
                .collect();
            let data: Vec<DataInfo> = children_by_tag(intent_filter, "data")
                .map(|d| DataInfo {
                    scheme: attr_str(d, "android:scheme"),
                    host: attr_str(d, "android:host"),
                    port: attr_str(d, "android:port"),
                    path: attr_str(d, "android:path"),
                    path_pattern: attr_str(d, "android:pathPattern"),
                    path_prefix: attr_str(d, "android:pathPrefix"),
                    mime_type: attr_str(d, "android:mimeType"),
                })
                .collect();
            IntentFilterInfo {
                actions,
                categories,
                data,
            }
        })
        .collect();

    ProviderInfo {
        name: attr_str(element, "android:name").unwrap_or_default(),
        authorities: attr_str(element, "android:authorities"),
        exported: attr_bool(element, "android:exported"),
        enabled: attr_bool(element, "android:enabled"),
        read_permission: attr_str(element, "android:readPermission"),
        write_permission: attr_str(element, "android:writePermission"),
        permission: attr_str(element, "android:permission"),
        grant_uri_permissions: attr_bool(element, "android:grantUriPermissions"),
        multiprocess: attr_bool(element, "android:multiprocess"),
        syncable: attr_bool(element, "android:syncable"),
        intent_filters,
    }
}

impl From<&AndroidManifest> for ManifestSummary {
    fn from(manifest: &AndroidManifest) -> Self {
        let root = manifest.root();
        let package_name = manifest.package_name().map(|s| s.to_string());
        let version_code = manifest
            .root()
            .attribute_value("android:versionCode")
            .map(|v| match v {
                ManifestValue::Integer(i) => i.to_string(),
                ManifestValue::String(s) => s.clone(),
                _ => format!("{:?}", v),
            });
        let version_name = manifest.version_name().map(|s| s.to_string());
        let install_location = attr_str(root, "android:installLocation");
        let platform_build_version_code =
            attr_str(root, "platformBuildVersionCode").or_else(|| {
                attr_str(root, "android:platformBuildVersionCode")
            });
        let platform_build_version_name =
            attr_str(root, "platformBuildVersionName").or_else(|| {
                attr_str(root, "android:platformBuildVersionName")
            });

        let uses_sdk = first_child_by_tag(root, "uses-sdk");
        let sdk = SdkInfo {
            min_sdk_version: uses_sdk
                .and_then(|e| attr_str(e, "android:minSdkVersion"))
                .or_else(|| attr_str(root, "android:minSdkVersion")),
            target_sdk_version: uses_sdk
                .and_then(|e| attr_str(e, "android:targetSdkVersion"))
                .or_else(|| attr_str(root, "android:targetSdkVersion")),
            max_sdk_version: uses_sdk
                .and_then(|e| attr_str(e, "android:maxSdkVersion"))
                .or_else(|| attr_str(root, "android:maxSdkVersion")),
        };

        let uses_permissions: Vec<String> = manifest
            .uses_permissions()
            .iter()
            .filter_map(|p| attr_str(p, "android:name"))
            .collect();

        let declares_permissions: Vec<PermissionDecl> =
            children_by_tag(root, "permission")
                .map(|p| PermissionDecl {
                    name: attr_str(p, "android:name").unwrap_or_default(),
                    protection_level: attr_str(p, "android:protectionLevel"),
                    label: attr_str(p, "android:label"),
                    description: attr_str(p, "android:description"),
                    permission_group: attr_str(p, "android:permissionGroup"),
                })
                .collect();

        let uses_features: Vec<FeatureInfo> = children_by_tag(root, "uses-feature")
            .map(|f| FeatureInfo {
                name: attr_str(f, "android:name"),
                gl_es_version: attr_str(f, "android:glEsVersion"),
                required: attr_bool(f, "android:required"),
            })
            .collect();

        let application = manifest.application().map(|app| {
            let activities: Vec<ComponentInfo> =
                children_by_tag(app, "activity").map(|e| extract_component(e)).collect();
            let services: Vec<ComponentInfo> =
                children_by_tag(app, "service").map(|e| extract_component(e)).collect();
            let receivers: Vec<ComponentInfo> =
                children_by_tag(app, "receiver").map(|e| extract_component(e)).collect();
            let providers: Vec<ProviderInfo> =
                children_by_tag(app, "provider").map(|e| extract_provider(e)).collect();
            let uses_libraries: Vec<LibraryInfo> =
                children_by_tag(app, "uses-library")
                    .map(|l| LibraryInfo {
                        name: attr_str(l, "android:name").unwrap_or_default(),
                        required: attr_bool(l, "android:required"),
                    })
                    .collect();
            let meta_data: Vec<MetaDataInfo> =
                children_by_tag(app, "meta-data")
                    .map(|m| MetaDataInfo {
                        name: attr_str(m, "android:name").unwrap_or_default(),
                        value: attr_str(m, "android:value"),
                        resource: attr_str(m, "android:resource"),
                    })
                    .collect();

            ApplicationSummary {
                label: attr_str(app, "android:label"),
                icon: attr_str(app, "android:icon"),
                name: attr_str(app, "android:name"),
                allow_backup: attr_bool(app, "android:allowBackup"),
                debuggable: attr_bool(app, "android:debuggable"),
                test_only: attr_bool(app, "android:testOnly"),
                has_code: attr_bool(app, "android:hasCode"),
                theme: attr_str(app, "android:theme"),
                allow_clear_user_data: attr_bool(app, "android:allowClearUserData"),
                hardware_accelerated: attr_bool(app, "android:hardwareAccelerated"),
                large_heap: attr_bool(app, "android:largeHeap"),
                supports_rtl: attr_bool(app, "android:supportsRtl"),
                activities,
                services,
                receivers,
                providers,
                uses_libraries,
                meta_data,
            }
        });

        let main_activity = application.as_ref().and_then(|app| {
            app.activities.iter().find_map(|a| {
                let is_launcher = a.intent_filters.iter().any(|f| {
                    f.actions.iter().any(|act| act == "android.intent.action.MAIN")
                        && f.categories.iter().any(|cat| cat == "android.intent.category.LAUNCHER")
                });
                if is_launcher { Some(a.name.clone()) } else { None }
            })
        });

        let instrumentation: Vec<InstrumentationInfo> =
            children_by_tag(root, "instrumentation")
                .map(|i| InstrumentationInfo {
                    name: attr_str(i, "android:name").unwrap_or_default(),
                    target_package: attr_str(i, "android:targetPackage"),
                    label: attr_str(i, "android:label"),
                    handle_profiling: attr_bool(i, "android:handleProfiling"),
                    functional_test: attr_bool(i, "android:functionalTest"),
                })
                .collect();

        let supports_screens = first_child_by_tag(root, "supports-screens").map(|s| {
            SupportsScreensInfo {
                resizeable: attr_bool(s, "android:resizeable"),
                small_screens: attr_bool(s, "android:smallScreens"),
                normal_screens: attr_bool(s, "android:normalScreens"),
                large_screens: attr_bool(s, "android:largeScreens"),
                xlarge_screens: attr_bool(s, "android:xlargeScreens"),
                any_density: attr_bool(s, "android:anyDensity"),
                requires_smallest_width_dp: attr_str(s, "android:requiresSmallestWidthDp"),
                compatible_width_limit_dp: attr_str(s, "android:compatibleWidthLimitDp"),
                largest_width_limit_dp: attr_str(s, "android:largestWidthLimitDp"),
            }
        });

        ManifestSummary {
            package_name,
            version_code,
            version_name,
            install_location,
            platform_build_version_code,
            platform_build_version_name,
            sdk,
            uses_permissions,
            declares_permissions,
            uses_features,
            main_activity,
            application,
            instrumentation,
            supports_screens,
        }
    }
}

impl ManifestSummary {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_yaml(&self) -> serde_yaml::Result<String> {
        serde_yaml::to_string(self)
    }

    pub fn to_printed(&self) -> String {
        let mut out = String::new();

        let hline = "=".repeat(60);
        out.push_str(&hline);
        out.push_str("\n                     ANDROID MANIFEST\n");
        out.push_str(&hline);
        out.push_str("\n\n");

        out.push_str("--- Identity ---\n");
        kv(&mut out, "Package", self.package_name.as_deref());
        kv(&mut out, "Version Code", self.version_code.as_deref());
        kv(&mut out, "Version Name", self.version_name.as_deref());
        kv(&mut out, "Install Location", self.install_location.as_deref());
        kv(
            &mut out,
            "Platform Build Version Code",
            self.platform_build_version_code.as_deref(),
        );
        kv(
            &mut out,
            "Platform Build Version Name",
            self.platform_build_version_name.as_deref(),
        );
        kv(&mut out, "Main Activity", self.main_activity.as_deref());
        out.push_str("\n");

        out.push_str("--- SDK ---\n");
        kv(&mut out, "Min SDK Version", self.sdk.min_sdk_version.as_deref());
        kv(
            &mut out,
            "Target SDK Version",
            self.sdk.target_sdk_version.as_deref(),
        );
        kv(
            &mut out,
            "Max SDK Version",
            Some(self.sdk.max_sdk_version.as_deref().unwrap_or("(none)")),
        );
        out.push_str("\n");

        if !self.uses_permissions.is_empty() || !self.declares_permissions.is_empty() {
            out.push_str(&format!(
                "--- Permissions ({} uses-permission, {} declared) ---\n",
                self.uses_permissions.len(),
                self.declares_permissions.len()
            ));
            for p in &self.uses_permissions {
                out.push_str(&format!("    \u{2022} {}\n", p));
            }
            for d in &self.declares_permissions {
                out.push_str(&format!("    \u{2022} {} (declared)\n", d.name));
                if let Some(ref lvl) = d.protection_level {
                    out.push_str(&format!("        Protection Level: {}\n", lvl));
                }
            }
            if !self.uses_permissions.is_empty() || !self.declares_permissions.is_empty() {
                out.push_str("\n");
            }
        }

        if !self.uses_features.is_empty() {
            out.push_str(&format!("--- Features ({}) ---\n", self.uses_features.len()));
            for f in &self.uses_features {
                if let Some(ref name) = f.name {
                    let req = f.required.map(|r| if r { "yes" } else { "no" });
                    out.push_str(&format!("    \u{2022} {}", name));
                    if let Some(r) = req {
                        out.push_str(&format!("    required: {}", r));
                    }
                    out.push_str("\n");
                } else if let Some(ref gl) = f.gl_es_version {
                    out.push_str(&format!("    \u{2022} OpenGL ES version: {}\n", gl));
                }
            }
            out.push_str("\n");
        }

        if let Some(ref app) = self.application {
            out.push_str("--- Application ---\n");
            kv(&mut out, "Label", app.label.as_deref());
            kv(&mut out, "Icon", app.icon.as_deref());
            kv(&mut out, "Name", app.name.as_deref());
            kv_bool(&mut out, "Allow Backup", app.allow_backup);
            kv_bool(&mut out, "Debuggable", app.debuggable);
            kv_bool(&mut out, "Test Only", app.test_only);
            kv_bool(&mut out, "Has Code", app.has_code);
            kv_bool(&mut out, "Hardware Accelerated", app.hardware_accelerated);
            kv_bool(&mut out, "Large Heap", app.large_heap);
            kv_bool(&mut out, "Supports RTL", app.supports_rtl);
            kv(&mut out, "Theme", app.theme.as_deref());
            out.push_str("\n");

            print_components(&mut out, "Activities", &app.activities);
            print_components(&mut out, "Services", &app.services);
            print_components(&mut out, "Receivers", &app.receivers);

            if !app.providers.is_empty() {
                out.push_str(&format!("\n    --- Providers ({}) ---\n", app.providers.len()));
                for p in &app.providers {
                    out.push_str(&format!("    \u{2022} {}\n", p.name));
                    if let Some(ref a) = p.authorities {
                        out.push_str(&format!("        Authorities: {}\n", a));
                    }
                    kv_bool_indent(&mut out, "Exported", p.exported, 8);
                    kv_str_indent(&mut out, "Read Permission", p.read_permission.as_deref(), 8);
                    kv_str_indent(&mut out, "Write Permission", p.write_permission.as_deref(), 8);
                    kv_str_indent(&mut out, "Permission", p.permission.as_deref(), 8);
                    kv_bool_indent(&mut out, "Grant URI Permissions", p.grant_uri_permissions, 8);
                }
                out.push_str("\n");
            }

            if !app.uses_libraries.is_empty() {
                out.push_str(&format!(
                    "\n    --- Libraries ({}) ---\n",
                    app.uses_libraries.len()
                ));
                for l in &app.uses_libraries {
                    let req = l.required.map(|r| if r { "yes" } else { "no" });
                    out.push_str(&format!("    \u{2022} {}", l.name));
                    if let Some(r) = req {
                        out.push_str(&format!("    required: {}", r));
                    }
                    out.push_str("\n");
                }
                out.push_str("\n");
            }

            if !app.meta_data.is_empty() {
                out.push_str(&format!(
                    "\n    --- Meta Data ({}) ---\n",
                    app.meta_data.len()
                ));
                for m in &app.meta_data {
                    out.push_str(&format!("    \u{2022} {}\n", m.name));
                    if let Some(ref v) = m.value {
                        out.push_str(&format!("        Value: {}\n", v));
                    }
                    if let Some(ref r) = m.resource {
                        out.push_str(&format!("        Resource: {}\n", r));
                    }
                }
                out.push_str("\n");
            }
        }

        if !self.instrumentation.is_empty() {
            out.push_str(&format!(
                "\n--- Instrumentation ({}) ---\n",
                self.instrumentation.len()
            ));
            for i in &self.instrumentation {
                out.push_str(&format!("    \u{2022} {}\n", i.name));
                if let Some(ref t) = i.target_package {
                    out.push_str(&format!("        Target Package: {}\n", t));
                }
                kv_bool_indent(&mut out, "Handle Profiling", i.handle_profiling, 8);
                kv_bool_indent(&mut out, "Functional Test", i.functional_test, 8);
            }
            out.push_str("\n");
        }

        if let Some(ref ss) = self.supports_screens {
            out.push_str("\n--- Supports Screens ---\n");
            kv_bool(&mut out, "Resizeable", ss.resizeable);
            kv_bool(&mut out, "Small Screens", ss.small_screens);
            kv_bool(&mut out, "Normal Screens", ss.normal_screens);
            kv_bool(&mut out, "Large Screens", ss.large_screens);
            kv_bool(&mut out, "XLarge Screens", ss.xlarge_screens);
            kv_bool(&mut out, "Any Density", ss.any_density);
            kv(
                &mut out,
                "Requires Smallest Width DP",
                ss.requires_smallest_width_dp.as_deref(),
            );
            kv(
                &mut out,
                "Compatible Width Limit DP",
                ss.compatible_width_limit_dp.as_deref(),
            );
            kv(
                &mut out,
                "Largest Width Limit DP",
                ss.largest_width_limit_dp.as_deref(),
            );
            out.push_str("\n");
        }

        out
    }
}

fn kv(out: &mut String, key: &str, value: Option<&str>) {
    let val = value.unwrap_or("(none)");
    out.push_str(&format!("  {:<30} {}\n", key, val));
}

fn kv_bool(out: &mut String, key: &str, value: Option<bool>) {
    let val = match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "(none)",
    };
    out.push_str(&format!("  {:<30} {}\n", key, val));
}

fn kv_str_indent(out: &mut String, key: &str, value: Option<&str>, indent: usize) {
    let prefix = " ".repeat(indent);
    let val = value.unwrap_or("(none)");
    out.push_str(&format!("{}  {:<26} {}\n", prefix, key, val));
}

fn kv_bool_indent(out: &mut String, key: &str, value: Option<bool>, indent: usize) {
    let prefix = " ".repeat(indent);
    let val = match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "(none)",
    };
    out.push_str(&format!("{}  {:<26} {}\n", prefix, key, val));
}

fn print_components(out: &mut String, label: &str, components: &[ComponentInfo]) {
    if components.is_empty() {
        return;
    }
    out.push_str(&format!("\n    --- {} ({}) ---\n", label, components.len()));
    for c in components {
        out.push_str(&format!("    \u{2022} {}\n", c.name));
        if let Some(e) = c.exported {
            out.push_str(&format!("        Exported: {}\n", if e { "true" } else { "false" }));
        }
        if let Some(e) = c.enabled {
            out.push_str(&format!("        Enabled: {}\n", if e { "true" } else { "false" }));
        }
        if let Some(ref p) = c.permission {
            out.push_str(&format!("        Permission: {}\n", p));
        }
        if let Some(ref p) = c.process {
            out.push_str(&format!("        Process: {}\n", p));
        }
        if let Some(ref l) = c.launch_mode {
            out.push_str(&format!("        Launch Mode: {}\n", l));
        }
        if let Some(ref o) = c.orientation {
            out.push_str(&format!("        Orientation: {}\n", o));
        }
        if let Some(ref cc) = c.config_changes {
            out.push_str(&format!("        Config Changes: {}\n", cc));
        }
        if let Some(ref pa) = c.parent_activity_name {
            out.push_str(&format!("        Parent Activity: {}\n", pa));
        }

        for intent_filter in &c.intent_filters {
            out.push_str("        Intent Filters:\n");
            if !intent_filter.actions.is_empty() {
                out.push_str(&format!(
                    "          actions: {}\n",
                    intent_filter.actions.join(", ")
                ));
            }
            if !intent_filter.categories.is_empty() {
                out.push_str(&format!(
                    "          categories: {}\n",
                    intent_filter.categories.join(", ")
                ));
            }
            for d in &intent_filter.data {
                let mut parts: Vec<&str> = Vec::new();
                if let Some(ref s) = d.scheme {
                    parts.push(s);
                }
                if let Some(ref h) = d.host {
                    parts.push(h);
                }
                if let Some(ref p) = d.port {
                    parts.push(p);
                }
                if let Some(ref p) = d.path {
                    parts.push(p);
                }
                if let Some(ref p) = d.path_pattern {
                    parts.push(p);
                }
                if let Some(ref p) = d.path_prefix {
                    parts.push(p);
                }
                if let Some(ref m) = d.mime_type {
                    parts.push(m);
                }
                if !parts.is_empty() {
                    out.push_str(&format!("          data: {}\n", parts.join(":")));
                }
            }
        }
    }
}
