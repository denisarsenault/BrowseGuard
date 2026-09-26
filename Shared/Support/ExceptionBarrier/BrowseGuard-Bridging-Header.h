// Bridging header for the three app targets.
//
// Only the app targets need this; the content blocker and web extension never
// talk to SafariServices, so they compile as pure Swift.

#import "BGExceptionBarrier.h"
