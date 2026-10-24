package in.bharatshield.verity;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.ViewGroup;
import android.webkit.ConsoleMessage;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;

import org.json.JSONObject;

/**
 * MainActivity — Native Android Bridge Host for Verity Shield
 *
 * Features:
 * 1. Full-screen hardware-accelerated WebView hosting Verity Shield.
 * 2. Intent Receiver for Android ACTION_SEND (WhatsApp/SMS text sharing).
 * 3. Deep-Link Receiver for ACTION_VIEW (http/https website and upi:// payment links).
 * 4. Bi-directional JavaScript bridge delivering intent payloads to window.VerityAndroidBridge.
 */
public class MainActivity extends Activity {

    private static final String TAG = "VerityMainActivity";
    private WebView webView;
    private boolean isPageLoaded = false;
    private String pendingPayloadJson = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Configure full-screen WebView layout
        FrameLayout rootLayout = new FrameLayout(this);
        rootLayout.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));

        webView = new WebView(this);
        webView.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));

        configureWebViewSettings(webView);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                isPageLoaded = true;
                Log.d(TAG, "WebView page finished loading: " + url);

                if (pendingPayloadJson != null) {
                    dispatchToJsBridge(pendingPayloadJson);
                    pendingPayloadJson = null;
                }
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onConsoleMessage(ConsoleMessage consoleMessage) {
                Log.d("VerityJS", consoleMessage.message() + " -- From line "
                        + consoleMessage.lineNumber() + " of " + consoleMessage.sourceId());
                return true;
            }
        });

        rootLayout.addView(webView);
        setContentView(rootLayout);

        // Load local bundled web assets
        webView.loadUrl("file:///android_asset/public/index.html");

        // Handle initial launch intent
        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIncomingIntent(intent);
    }

    /**
     * Inspects incoming intent (share target or deep link) and serializes into bridge JSON.
     */
    private void handleIncomingIntent(Intent intent) {
        if (intent == null) return;

        String action = intent.getAction();
        String type = intent.getType();

        try {
            JSONObject payload = new JSONObject();

            if (Intent.ACTION_SEND.equals(action) && type != null) {
                if ("text/plain".equals(type)) {
                    String sharedText = intent.getStringExtra(Intent.EXTRA_TEXT);
                    if (sharedText != null && !sharedText.trim().isEmpty()) {
                        payload.put("type", "shared_text");
                        payload.put("data", sharedText.trim());
                        Log.d(TAG, "Received shared text: " + sharedText);
                        deliverPayload(payload.toString());
                    }
                }
            } else if (Intent.ACTION_VIEW.equals(action)) {
                Uri dataUri = intent.getData();
                if (dataUri != null) {
                    String uriString = dataUri.toString().trim();
                    String scheme = dataUri.getScheme();

                    if ("upi".equalsIgnoreCase(scheme)) {
                        payload.put("type", "payment");
                        payload.put("data", uriString);
                    } else if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
                        payload.put("type", "url");
                        payload.put("data", uriString);
                    } else {
                        payload.put("type", "general");
                        payload.put("data", uriString);
                    }

                    Log.d(TAG, "Received deep link VIEW intent: " + uriString);
                    deliverPayload(payload.toString());
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error parsing incoming intent: " + e.getMessage(), e);
        }
    }

    /**
     * Delivers JSON payload to JavaScript window.VerityAndroidBridge.
     */
    private void deliverPayload(String jsonString) {
        if (isPageLoaded && webView != null) {
            dispatchToJsBridge(jsonString);
        } else {
            pendingPayloadJson = jsonString;
        }
    }

    private void dispatchToJsBridge(String jsonString) {
        if (webView == null) return;
        final String script = "window.VerityAndroidBridge && window.VerityAndroidBridge.onIncomingIntent(" + jsonString + ");";
        webView.post(new Runnable() {
            @Override
            public void run() {
                webView.evaluateJavascript(script, null);
                Log.d(TAG, "Dispatched intent payload to window.VerityAndroidBridge");
            }
        });
    }

    private void configureWebViewSettings(WebView wv) {
        WebSettings settings = wv.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setLoadsImagesAutomatically(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);

        wv.setLayerType(WebView.LAYER_TYPE_HARDWARE, null);
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
