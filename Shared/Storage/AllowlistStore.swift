import Foundation

/// File-coordinated access to the allowlist.
///
/// The host app owns the allowlist for editing, but the Safari extension has to
/// be able to add a temporary bypass the moment the user presses "Continue
/// anyway" on the block page — the app may not even be running. Both processes
/// therefore go through `NSFileCoordinator` here.
public enum AllowlistStore {

    public static func load() -> Allowlist {
        SharedStore.allowlist()
    }

    /// Adds a time-boxed bypass and returns the updated allowlist.
    @discardableResult
    public static func addTemporaryBypass(
        host rawHost: String,
        category: ThreatCategory?,
        duration: TimeInterval
    ) -> Allowlist {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else { return load() }
        return mutate { allowlist in
            allowlist.pruneExpired()
            allowlist.add(AllowlistItem(
                host: host,
                expiresAt: .now.addingTimeInterval(duration),
                bypassedCategory: category
            ))
        }
    }

    @discardableResult
    public static func add(host rawHost: String) -> Allowlist {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else { return load() }
        return mutate { allowlist in
            allowlist.pruneExpired()
            allowlist.add(AllowlistItem(host: host))
        }
    }

    @discardableResult
    public static func remove(host rawHost: String) -> Allowlist {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else { return load() }
        return mutate { $0.remove(host: host) }
    }

    private static func mutate(_ body: (inout Allowlist) -> Void) -> Allowlist {
        guard let url = AppGroup.File.allowlist.url else {
            var allowlist = load()
            body(&allowlist)
            return allowlist
        }

        var result = Allowlist.empty
        var coordinationError: NSError?
        NSFileCoordinator().coordinate(
            writingItemAt: url,
            options: .forMerging,
            error: &coordinationError
        ) { _ in
            var allowlist = load()
            body(&allowlist)
            SharedStore.write(allowlist, to: .allowlist)
            result = allowlist
        }

        if coordinationError != nil {
            var allowlist = load()
            body(&allowlist)
            SharedStore.write(allowlist, to: .allowlist)
            return allowlist
        }
        return result
    }
}
