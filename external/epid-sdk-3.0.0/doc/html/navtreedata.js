var NAVTREE =
[
  [ "Intel® Enhanced Privacy ID SDK", "index.html", [
    [ " ", "user", null ],
    [ "Introducing the Intel® EPID SDK", "index.html", null ],
    [ "Legal Information", "LegalInformation.html", null ],
    [ "What's New", "ChangeLog.html", null ],
    [ "Introduction to the Intel® EPID Scheme", "EpidOverview.html", [
      [ "Roles", "EpidOverview.html#EpidOverview_Roles", [
        [ "Issuers", "EpidOverview.html#EpidOverview_Issuers", null ],
        [ "Members", "EpidOverview.html#EpidOverview_Members", null ],
        [ "Verifiers", "EpidOverview.html#EpidOverview_Verifiers", null ]
      ] ],
      [ "Groups", "EpidOverview.html#EpidOverview_Groups", null ],
      [ "Keys", "EpidOverview.html#EpidOverview_Keys", [
        [ "Group Public Key", "EpidOverview.html#EpidOverview_Group_public_key", null ],
        [ "Issuing Private Key", "EpidOverview.html#EpidOverview_Issuing_private_key", null ],
        [ "Member Private Key", "EpidOverview.html#EpidOverview_Member_private_key", null ]
      ] ],
      [ "Member and Verifier Interaction", "EpidOverview.html#EpidOverview_Entity_interaction", null ]
    ] ],
    [ "What's Included in the SDK", "SdkOverview.html", [
      [ "SDK Components", "SdkOverview.html#SdkOverview_Components", null ],
      [ "Filesystem Layout", "SdkOverview.html#SdkOverview_Files", [
        [ "Source Layout", "SdkOverview.html#SdkOverview_Files_SourceLayout", null ],
        [ "Install Layout", "SdkOverview.html#SdkOverview_Files_InstallLayout", null ]
      ] ]
    ] ],
    [ "Building from Source", "BuildingSdk.html", [
      [ "Prerequisites", "BuildingSdk.html#BuildingSdk_Prerequisites", null ],
      [ "Building SDK with SCons", "BuildingSdk.html#BuildingSdk_Building_SCons", null ],
      [ "Alternate Makefile/Autoconf Based Build Approach", "BuildingSdk.html#BuildingSdk_Building_Makefile", null ],
      [ "Improving Performance with Commercial IPP", "BuildingSdk.html#BuildingSdk_CommercialIpp", null ],
      [ "Example Programs", "BuildingSdk.html#BuildingSdk_Examples", null ],
      [ "Building with Other Build Systems", "BuildingSdk.html#BuildingSdk_PortingBuildSystem", null ]
    ] ],
    [ "Signing and Verification Tutorial", "SignVerifyTutorial.html", [
      [ "Creating an Intel® EPID Signature of a Given Message", "SignVerifyTutorial.html#SignVerifyTutorial_Signmmsg", null ],
      [ "Verifying an Intel® EPID Signature", "SignVerifyTutorial.html#SignVerifyTutorial_Verifysig", null ],
      [ "Linking Intel® EPID Signatures from the Same Member", "SignVerifyTutorial.html#SignVerifyTutorial_Basename", null ],
      [ "Expected Failures", "SignVerifyTutorial.html#SignVerifyTutorial_VerificationFailures", null ],
      [ "Revocation", "SignVerifyTutorial.html#SignVerifyTutorial_Revocation_Group", [
        [ "Detecting Revoked Group from Group Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_GroupRevocation", null ],
        [ "Detecting Revoked Member from Private Key Based Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_KeyRevocation", null ],
        [ "Detecting Revoked Member from Signature Based Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_SigRevocation", null ]
      ] ]
    ] ],
    [ "Sample Issuer Material", "IssuerMaterial.html", [
      [ "Sample Groups", "IssuerMaterial.html#IssuerMaterial_Groups", [
        [ "Sample Group A", "IssuerMaterial.html#IssuerMaterial_Groups_groupa", null ],
        [ "Sample Group B", "IssuerMaterial.html#IssuerMaterial_Groups_groupb", null ]
      ] ],
      [ "Group Based Revocation Lists", "IssuerMaterial.html#IssuerMaterial_GroupRls", null ],
      [ "Compressed Member Private Key", "IssuerMaterial.html#IssuerMaterial_CmpGroups", [
        [ "Compressed Sample Group A", "IssuerMaterial.html#IssuerMaterial_CmpGroups_groupa", null ],
        [ "Compressed Sample Group B", "IssuerMaterial.html#IssuerMaterial_CmpGroups_groupb", null ]
      ] ],
      [ "Compressed Group Based Revocation Lists", "IssuerMaterial.html#IssuerMaterial_CmpGroupRls", null ]
    ] ],
    [ "If You Choose iKGF as Your Issuer", "ChoosingiKGF.html", [
      [ "Tools for Creating Revocation Requests", "ChoosingiKGF.html#RevocationTools", [
        [ "Requesting Group Revocation", "ChoosingiKGF.html#RevocationTools_revokegrp", null ],
        [ "Requesting Private Key Revocation", "ChoosingiKGF.html#RevocationTools_revokekey", null ],
        [ "Requesting Signature Revocation", "ChoosingiKGF.html#RevocationTools_revokesig", null ]
      ] ],
      [ "Tools for Extracting Keys from iKGF Files", "ChoosingiKGF.html#ExtractionTools", [
        [ "Extracting Group Public Keys", "ChoosingiKGF.html#ExtractionTools_extractgrps", null ],
        [ "Extracting Member Private Keys", "ChoosingiKGF.html#ExtractionTools_extractkeys", null ]
      ] ]
    ] ],
    [ "In-Depth Explanation of Revocation", "Revocation.html", [
      [ "Revocation Hierarchy", "Revocation.html#revocation_hierarchy", null ],
      [ "Revocation List Versions", "Revocation.html#revocation_versions", null ],
      [ "Group Based Revocation", "Revocation.html#group_revocation", [
        [ "Reasons the Issuer Might Revoke a Group", "Revocation.html#group_revocation_reasons", null ]
      ] ],
      [ "Private Key Based Revocation", "Revocation.html#private_key_revocation", [
        [ "Reasons the Issuer Might Revoke a Member Private Key", "Revocation.html#private_key_revocation_reasons", null ]
      ] ],
      [ "Signature Based Revocation", "Revocation.html#signature_revocation", [
        [ "Signing with Non-Revoked Proofs", "Revocation.html#revoked_proofs", null ],
        [ "Reasons the Issuer Might Revoke an Intel® EPID Signature", "Revocation.html#signature_revocation_reasons", null ]
      ] ],
      [ "Verifier Blacklist Revocation", "Revocation.html#verifier_blacklist", [
        [ "Reasons the Verifier Might Revoke an Intel® EPID Signature", "Revocation.html#verifier_blacklist_reasons", null ]
      ] ]
    ] ],
    [ "In-Depth Explanation of Basenames", "Basenames.html", [
      [ "Random Base Signatures", "Basenames.html#random_base", null ],
      [ "Name Based Signatures", "Basenames.html#name_based", null ]
    ] ],
    [ "Implementation Notes", "ImplementationNotes.html", [
      [ "Random Number Generation", "ImplementationNotes.html#ImplementationNotes_Prng", null ],
      [ "Protecting Secrets", "ImplementationNotes.html#ImplementationNotes_ProtectingSecrets", null ],
      [ "Replacing Math Primitives", "ImplementationNotes.html#ImplementationNotes_MathPrimitives", null ],
      [ "Octstring/Buffer Types", "ImplementationNotes.html#ImplementationNotes_SerializedTypes", null ],
      [ "Flexible Arrays", "ImplementationNotes.html#ImplementationNotes_FlexibleArrays", null ]
    ] ],
    [ "Glossary", "Glossary.html", [
      [ "CA public key", "Glossary.html#Issuing_CA", null ],
      [ "DAA", "Glossary.html#Glossary_Daa", null ],
      [ "Elliptic curve", "Glossary.html#Glossary_EllipticCurve", null ],
      [ "Elliptic curve point", "Glossary.html#Glossary_EllipticCurvePoint", null ],
      [ "Group", "Glossary.html#Glossary_Group", null ],
      [ "Group certificate", "Glossary.html#Glossary_Group_certificate", null ],
      [ "Group public key", "Glossary.html#Glossary_GroupPublicKey", null ],
      [ "Intel® EPID", "Glossary.html#Glossary_Epid", null ],
      [ "Intel® EPID signature", "Glossary.html#Glossary_EpidSignature", null ],
      [ "Issuer", "Glossary.html#Glossary_Issuer", null ],
      [ "Issuing private key", "Glossary.html#Glossary_IssuingPrivateKey", null ],
      [ "Member", "Glossary.html#Glossary_Member", null ],
      [ "Name-based signature", "Glossary.html#Glossary_NameBasedSignature", null ],
      [ "Member private key", "Glossary.html#Glossary_MemberPrivateKey", null ],
      [ "Non-revoked proof", "Glossary.html#Glossary_NonRevokedProof", null ],
      [ "Pairing", "Glossary.html#Glossary_Pairing", null ],
      [ "Revocation, revocation lists", "Glossary.html#Glossary_Revocation", null ],
      [ "Verifier", "Glossary.html#Glossary_Verifier", null ]
    ] ],
    [ "Guide to Installing Build Tools", "BuildToolsInstallation.html", [
      [ "Installing Python", "BuildToolsInstallation.html#build_tools_windows_python", null ],
      [ "Installing SCons", "BuildToolsInstallation.html#build_tools_windows_scons", null ],
      [ "Installing Parts", "BuildToolsInstallation.html#build_tools_windows_parts", null ]
    ] ],
    [ "Walkthroughs of Examples Showing API Usage", "Examples.html", "Examples" ],
    [ "API Reference", "modules.html", "modules" ]
  ] ]
];

var NAVTREEINDEX =
[
"Basenames.html",
"group___error_codes.html#ggafdb27c77c2c4b32c807e326a8a0da360a8a6861e14322ca9193498ffc955537f9",
"struct_oct_str32.html#a5588a7e70f3d73f6ce58b567a9f5c5c8"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';