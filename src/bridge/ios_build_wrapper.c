/*
 * iOS Build Wrapper
 * 
 * This file provides iOS-specific compatibility by including
 * the iOS compatibility header before any SoftEther code.
 * 
 * This allows us to build SoftEther on iOS without modifying
 * the original SoftEtherVPN source code.
 */

// Include iOS compatibility definitions FIRST
#include "ios_compat.h"

// Now we can safely include SoftEther headers
// The ios_compat.h will provide missing definitions

// This file is intentionally minimal - it just ensures
// ios_compat.h is included in the compilation unit
