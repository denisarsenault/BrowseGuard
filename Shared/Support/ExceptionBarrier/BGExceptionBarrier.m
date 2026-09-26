#import "BGExceptionBarrier.h"

BOOL BGRunCatchingExceptions(void (NS_NOESCAPE ^block)(void),
                             NSString *_Nullable *_Nullable reason) {
    @try {
        block();
        return YES;
    } @catch (NSException *exception) {
        if (reason != NULL) {
            *reason = [NSString stringWithFormat:@"%@: %@",
                       exception.name,
                       exception.reason ?: @"no reason given"];
        }
        return NO;
    }
}
