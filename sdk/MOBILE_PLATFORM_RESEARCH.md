# Mobile Platform Research — Shyware SDK & Consumer Apps

Reference for building iOS (SwiftUI) and Android (Kotlin/Compose) SDK clients and consumer apps.
Researched May 2026. Re-use this doc rather than re-searching.

---

## iOS 26 / SwiftUI (Xcode 26, Swift 6.2)

### Deployment target
- Minimum: **iOS 26.0** for Liquid Glass; iOS 17 for @Observable without Glass
- Swift tools version: **6.2**
- Xcode: **26**

### State & concurrency
```swift
// Swift 6.2 approachable concurrency: @MainActor implicit on all code by default
// No longer need explicit @MainActor annotation on every @Observable class

@Observable          // replaces ObservableObject + @Published entirely
final class FooModel {
    var items: [Item] = []        // auto-tracked, no @Published needed
    var isLoading = false

    func load() async {
        isLoading = true
        defer { isLoading = false }
        items = try await repository.fetch()
    }
}

// In views — @State keeps model alive across redraws (replaces @StateObject)
struct FooView: View {
    @State private var model = FooModel()
    var body: some View { ... }
}

// Passed-down models — @Bindable for two-way binding on @Observable
struct ChildView: View {
    @Bindable var model: FooModel
}

// Environment injection
.environment(model)            // set
@Environment(FooModel.self) var model   // read
```

### Navigation (NavigationStack — no new iOS 26 API needed)
```swift
@Observable final class Router {
    var path = NavigationPath()
    func push<T: Hashable>(_ route: T) { path.append(route) }
    func pop() { path.removeLast() }
    func popToRoot() { path = NavigationPath() }
}

struct RootView: View {
    @State private var router = Router()
    var body: some View {
        NavigationStack(path: $router.path) {
            ContentView()
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .ballot(let pollId): BallotView(pollId: pollId)
                    case .tally(let pollId):  TallyView(pollId: pollId)
                    }
                }
        }
        .environment(router)
    }
}
```

NavigationStack + TabView automatically adopt Liquid Glass when recompiled against iOS 26 SDK — no code changes needed.

### Liquid Glass (iOS 26+)
```swift
// Core modifier — applies translucent glass behind content
.glassEffect()                                          // default: .regular, .capsule shape
.glassEffect(.regular.tint(.blue).interactive())       // tinted, interactive
.glassEffect(.regular, in: RoundedRectangle(cornerRadius: 16))
.glassEffect(.clear)                                   // high-transparency (media)

// Morphing transitions between glass elements
@Namespace private var glassNamespace

GlassEffectContainer(spacing: 8) {
    Button("A") { ... }.glassEffectID("a", in: glassNamespace)
    Button("B") { ... }.glassEffectID("b", in: glassNamespace)
}

// Button styles
.buttonStyle(.glass)             // translucent secondary
.buttonStyle(.glassProminent)    // opaque primary

// Tab bar accessory (persistent view above tab bar)
.tabViewBottomAccessory { WriteOnlyBadge() }
.tabBarMinimizeBehavior(.onScrollDown)

// ToolbarSpacer
ToolbarItem { ToolbarSpacer(.flexible()) }

// Navigation zoom transition
.navigationTransition(.zoom(sourceID: itemId, in: namespace))
```

**Rules:**
- Wrap multiple glass elements in `GlassEffectContainer` — prevents glass-on-glass sampling
- Glass belongs on the navigation/control layer, not main content
- Use `.identity` variant to conditionally disable without layout recalc
- Accessibility (Reduce Transparency, Increase Contrast) handled automatically

### Sheets & presentations
```swift
.sheet(isPresented: $showSheet) { Content() }
.presentationDetents([.medium, .large])
.presentationDragIndicator(.visible)
// Sheet auto-gets glass inset background on iOS 26
```

### TabView (iOS 26)
```swift
TabView {
    Tab("Home",   systemImage: "house")         { HomeView() }
    Tab("Search", systemImage: "magnifyingglass", role: .search) { SearchView() }
    Tab("Profile",systemImage: "person.circle") { ProfileView() }
}
```

### Rich text (iOS 26)
- `TextEditor` now supports `AttributedString` for rich text editing
- New APIs for custom controls over editor content

### Async patterns
```swift
// Task on appear
.task { await model.load() }
.task(id: pollId) { await model.loadPoll(pollId) }   // re-runs when id changes

// Structured concurrency for parallel fetches
async let tally   = client.getTally(pollId)
async let records = client.getVotes(pollId)
let (t, r) = try await (tally, records)
```

### App Attest (required for recoverable posture)
```swift
import DeviceCheck

// Already implemented in Shyware-iOS-client via AppAttestProvider
// Key flow:
// 1. AppAttestProvider.resolveSignals(network:) → RuntimeSignals
// 2. VotingClient.from(config, assertionProvider: attester.assertionProvider())
// 3. client.setRuntimeSignals(signals)
// 4. client.fetchOperatorPosture()
// 5. client.effectivePosture() → write_only | recoverable
```

---

## Android 16 / Jetpack Compose 1.11 (API level 36)

### Deployment target
- **minSdk: 26** (Android 8.0) for broad reach
- **targetSdk / compileSdk: 36** (Android 16)
- Compose BOM: **2026.04.01** (Compose 1.11.0 stable)
- Compose 1.12.0 will require compileSdk 37 + AGP 9

```kotlin
// build.gradle.kts (app)
android {
    compileSdk = 36
    defaultConfig { targetSdk = 36; minSdk = 26 }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.04.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.navigation:navigation-compose:2.9.0")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")
    implementation("com.google.dagger:hilt-android:2.55")
    kapt("com.google.dagger:hilt-compiler:2.55")
}
```

### Architecture: MVVM + MVI hybrid (2026 standard)
```kotlin
// ViewModel — single UiState StateFlow + SharedFlow for one-off events
@HiltViewModel
class BallotViewModel @Inject constructor(
    private val client: VotingClient,
) : ViewModel() {

    private val _state = MutableStateFlow(BallotUiState())
    val state: StateFlow<BallotUiState> = _state.asStateFlow()

    // One-off navigation/toast events — SharedFlow, NOT StateFlow
    private val _events = MutableSharedFlow<BallotEvent>()
    val events: SharedFlow<BallotEvent> = _events.asSharedFlow()

    fun castBallot(pollId: String, choice: String, personId: String) {
        viewModelScope.launch {
            _state.update { it.copy(isSubmitting = true) }
            try {
                val result = client.castSubmission(pollId, choice, IdentityInput.Didit(personId))
                _state.update { it.copy(isSubmitting = false, ballotId = result.submissionId) }
                _events.emit(BallotEvent.Success(result.submissionId))
            } catch (e: Exception) {
                _state.update { it.copy(isSubmitting = false, error = e.message) }
            }
        }
    }
}

data class BallotUiState(
    val isSubmitting: Boolean = false,
    val ballotId: String? = null,
    val error: String? = null,
)
sealed class BallotEvent {
    data class Success(val ballotId: String) : BallotEvent()
    data class NavigateTo(val route: String) : BallotEvent()
}
```

### Composable pattern (2026)
```kotlin
@Composable
fun BallotScreen(
    viewModel: BallotViewModel = hiltViewModel(),
    onNavigate: (String) -> Unit,
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current

    // Collect one-off events
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is BallotEvent.Success -> onNavigate("tally/${event.ballotId}")
            }
        }
    }

    BallotContent(state = state, onCast = viewModel::castBallot)
}
```

### Navigation (Compose Navigation 2.9)
```kotlin
// Type-safe routes with @Serializable (Navigation 2.8+)
@Serializable object HomeRoute
@Serializable data class BallotRoute(val pollId: String)
@Serializable data class TallyRoute(val pollId: String)

NavHost(navController, startDestination = HomeRoute) {
    composable<HomeRoute> { HomeScreen(onNavigate = { navController.navigate(BallotRoute(it)) }) }
    composable<BallotRoute> { backStackEntry ->
        val route: BallotRoute = backStackEntry.toRoute()
        BallotScreen(pollId = route.pollId, onNavigate = { navController.navigate(TallyRoute(it)) })
    }
    composable<TallyRoute> { backStackEntry ->
        val route: TallyRoute = backStackEntry.toRoute()
        TallyScreen(pollId = route.pollId)
    }
}
```

### Android 16 mandatory changes
- **Edge-to-edge display mandatory** — `WindowCompat.setDecorFitsSystemWindows(window, false)` no longer optional
- `Modifier.windowInsetsPadding(WindowInsets.systemBars)` required on root Scaffold
- **Large screen**: apps targeting API 36 must fill entire display (no pillarboxing); use `WindowSizeClass` for adaptive layouts
- **Trackpad**: trackpad events now `PointerType.Mouse` — gesture detection updated automatically in Compose 1.11
- `compileSdk 37` + AGP 9 required for Compose 1.12 (plan ahead)

### Material 3 / Edge-to-edge Scaffold
```kotlin
Scaffold(
    modifier = Modifier.fillMaxSize(),
    topBar = { TopAppBar(title = { Text("Title") }) },
    bottomBar = { NavigationBar { /* tabs */ } },
    contentWindowInsets = WindowInsets.safeDrawing,  // Android 16 required
) { padding ->
    Content(modifier = Modifier.padding(padding))
}
```

### Play Integrity (required for recoverable posture)
```kotlin
// Already in shyware/sdk/android PlayIntegrityProvider
// Key flow:
// 1. PlayIntegrityProvider(context, cloudProjectNumber)
// 2. val (signals, token) = integrity.requestIntegrityToken(nonce)
// 3. verify token server-side → get trusted boolean
// 4. client.setRuntimeSignals(if (trusted) signals else RuntimeSignals.untrusted)
// 5. val posture = client.effectivePosture()
```

### Compose 1.11 new experimental APIs to adopt
- **Styles API**: state-based styling with transitions — use over repeated modifier chains
- **MediaQuery / UiMediaScope**: adaptive layouts for foldables, tablets
- **Grid layout**: 2D layouts without LazyVerticalGrid boilerplate
- **FlexBox**: wrapping adaptive containers
- Testing: V2 APIs now default; `StandardTestDispatcher` replaces `UnconfinedTestDispatcher`

---

## SDK client parity target

Both platforms must implement the same set of clients, mirroring the JS SDK:

| JS client | iOS Swift | Android Kotlin |
|---|---|---|
| `votingClient.js` | `VotingClient` ✅ (exists) | `VotingClient` ✅ (exists, partial) |
| `wireClient.js` | `WireClient` ❌ | `WireClient` ❌ |
| `custodyClient.js` | `CustodyClient` ❌ | `CustodyClient` ❌ |
| `contractsClient.js` | `ContractsClient` ❌ | `ContractsClient` ❌ |
| `sharesClient.js` | `SharesClient` ❌ | `SharesClient` ❌ |
| `betsClient.js` | `BetsClient` ❌ | `BetsClient` ❌ |
| `lotsClient.js` | `LotsClient` ❌ | `LotsClient` ❌ |
| `storeClient.js` | `StoreClient` ❌ | `StoreClient` ❌ |
| `chatClient.js` | `ChatClient` ❌ | `ChatClient` ❌ |
| `browserClient.js` | `BrowserClient` ❌ | `BrowserClient` ❌ |
| `streamClient.js` | `StreamClient` ❌ | `StreamClient` ❌ |
| `restClient.js` | `RestClient` ❌ | `RestClient` ❌ |

### Shared SDK requirements (both platforms)
- `ShyConfig` / `ShyConfig.kt` — shyconfig manifest decoder ✅ both
- `IdentityInput` — provider-agnostic identity sealed type ✅ both
- `createIdentityCommitment()` — SHA-256 derivation ✅ both
- `createIdentityProofHash()` — proof hash derivation ✅ both
- `ReceiptStore` — Keychain (iOS) / EncryptedSharedPreferences (Android) ✅ both
- `WriteOnlyPosture` / posture resolver ✅ both
- `AppAttestProvider` (iOS) / `PlayIntegrityProvider` (Android) ✅ both
- `VotingClient` — voting embodiment ✅ both (Android partial)
- All other clients — ❌ missing on both platforms

---

## Build order

1. Wire Android VotingClient into SEDA_HAQQ (replace BallotCrypto + raw ApiClient)
2. Build remaining Android SDK clients (wire, custody, contracts, shares, store, chat, browser, stream, rest, bets, lots)
3. Upgrade Stack 5 (Swift) + Stack 6 (Kotlin) DPIA tests to use SDK clients
4. Build iOS SDK clients (wire, custody, contracts, shares, store, chat, browser, stream, rest, bets, lots)
5. Build iOS SwiftUI consumer apps (starting with POP-U-LIST which already has scaffold)
6. Build Android Kotlin/Compose consumer apps (starting with SEDA_HAQQ which already has scaffold)
