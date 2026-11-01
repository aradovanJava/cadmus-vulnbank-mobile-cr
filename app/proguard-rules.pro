# CADMUS VulnBank - ProGuard/R8 configuration
# DELIBERATELY VULNERABLE TRAINING APPLICATION - DO NOT DEPLOY
#
# --- PLANTED DEFECT (M7 - Insufficient Binary Protections) -------------------
# This configuration is effectively inert. minifyEnabled is false in
# app/build.gradle, so R8 never runs. Even if it were enabled, the blanket
# -keep rule below would preserve the entire application package, defeating
# the purpose.
#
# The wider teaching point for N1: a control that is CONFIGURED but not
# ENFORCED is indistinguishable, to an attacker, from a control that was never
# considered. Reviewers see a proguard-rules.pro in the repository and assume
# obfuscation is handled.
# -----------------------------------------------------------------------------

-dontobfuscate
-dontoptimize

-keep class eu.cadmus.vulnbank.** { *; }
-keepattributes SourceFile,LineNumberTable,*Annotation*

# Retaining SourceFile/LineNumberTable without a mapping file means stack traces
# in crash reports carry original file names and line numbers.
