import Foundation

/// File-coordinated access to the user's own block list.
///
/// The counterpart to `AllowlistStore`, and it exists for the same reason: the
/// Safari extension must be able to block a site straight from the popup, in
/// its own process, whether or not the app is running.
public enum UserBlocklistStore {

    public static func load() -> UserBlocklist {
        SharedStore.userBlocklist()
    }

    @discardableResult
    public static func add(host rawHost: String, note: String? = nil) -> UserBlocklist {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else { return load() }
        // Blocking something previously allowed should just work, rather than
        // silently losing to a stale allowlist entry — same rule the app
        // applies in `ProtectionCoordinator.block`.
        AllowlistStore.remove(host: host)
        return mutate { $0.add(BlockedSite(host: host, note: note)) }
    }

    @discardableResult
    public static func remove(host rawHost: String) -> UserBlocklist {
        guard let host = URLNormalizer.canonicalHost(of: rawHost) else { return load() }
        return mutate { $0.remove(host: host) }
    }

    private static func mutate(_ body: (inout UserBlocklist) -> Void) -> UserBlocklist {
        guard let url = AppGroup.File.userBlocklist.url else {
            var list = load()
            body(&list)
            return list
        }

        var result = UserBlocklist.empty
        var coordinationError: NSError?
        NSFileCoordinator().coordinate(
            writingItemAt: url,
            options: .forMerging,
            error: &coordinationError
        ) { _ in
            var list = load()
            body(&list)
            SharedStore.write(list, to: .userBlocklist)
            result = list
        }

        if coordinationError != nil {
            var list = load()
            body(&list)
            SharedStore.write(list, to: .userBlocklist)
            return list
        }
        return result
    }
}
