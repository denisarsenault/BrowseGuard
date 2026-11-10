import Foundation

/// Decides when to raise the one-time "you have an old copy, clean it up" prompt
/// after an update.
///
/// Pure so it is testable without a real defaults store or a second app on disk.
/// The rule: prompt only when a duplicate exists, and at most once per app
/// version — so a user who chooses to keep both copies is not nagged on every
/// launch, but a fresh update (which is the moment an old copy becomes stale)
/// gets one reminder.
public enum DuplicateInstallPrompt {

    /// - Parameters:
    ///   - hasDuplicates: whether more than one copy is installed right now.
    ///   - currentVersion: this build's version+build string.
    ///   - lastPromptedVersion: the version we last showed the prompt for, if any.
    public static func shouldPrompt(hasDuplicates: Bool,
                                    currentVersion: String,
                                    lastPromptedVersion: String?) -> Bool {
        guard hasDuplicates else { return false }
        return currentVersion != lastPromptedVersion
    }
}
