#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Runs `block`, converting any Objective-C exception it raises into a `NO`
/// return instead of terminating the process.
///
/// This exists for exactly one reason: the SafariServices XPC calls
/// (`SFContentBlockerManager`, `SFSafariExtensionManager`) can raise
/// `NSInvalidArgumentException` from deep inside an `NSXPCConnection` proxy
/// when Safari's helper rejects the selector they send — which happens on an
/// unsigned or unsandboxed build, where the framework cannot mint the sandbox
/// extension token its private selector expects.
///
/// Swift has no `catch` for an `NSException`, so without this shim an
/// onboarding status check takes the whole app down. Reporting "I can't tell
/// whether the extension is enabled" is always better than crashing a security
/// app on a user's Mac.
///
/// This is not a general-purpose error mechanism. An `NSException` leaves
/// unknown state behind, so use it only at a boundary like this one, where the
/// only thing being abandoned is a single read-only query.
BOOL BGRunCatchingExceptions(void (NS_NOESCAPE ^block)(void),
                             NSString *_Nullable *_Nullable reason);

NS_ASSUME_NONNULL_END
