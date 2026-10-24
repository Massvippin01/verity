package in.bharatshield.verity;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * VerityNotificationService — Background SMS & WhatsApp Phishing Sentinel
 *
 * Extends Android NotificationListenerService to intercept incoming message notifications
 * from messaging and SMS applications, scanning for cyber fraud keywords and suspicious links in real time.
 */
public class VerityNotificationService extends NotificationListenerService {

    private static final String TAG = "VerityNotifSentinel";
    private static final String CHANNEL_ID = "verity_threat_alerts";

    // Known messaging & SMS package identifiers
    private static final Set<String> MONITORED_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.apps.messaging",
            "com.samsung.android.messaging",
            "com.whatsapp",
            "com.whatsapp.w4b",
            "org.telegram.messenger",
            "com.android.mms"
    ));

    // High-risk Indian cyber fraud indicators
    private static final Pattern HIGH_RISK_LURE_PATTERN = Pattern.compile(
            "(?i)(?:digital\\s*arrest|cbi\\s*cyber|narcotics\\s*parcel|customs\\s*seizure|electricity\\s*disconnect|power\\s*disconnect|bill\\s*unpaid|kyc\\s*blocked|pan\\s*blocked|sim\\s*deactivation|upi:\\/\\/pay|rto_challan|wedding_card\\.apk|pm_kisan\\.apk)"
    );

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)https?:\\/\\/[^\\s]+"
    );

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        Log.d(TAG, "Verity Notification Sentinel active.");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null) return;

        String packageName = sbn.getPackageName();
        if (packageName == null || packageName.equals(getPackageName())) {
            return; // Ignore internal notifications
        }

        if (!MONITORED_PACKAGES.contains(packageName)) {
            return;
        }

        try {
            Notification notification = sbn.getNotification();
            if (notification == null || notification.extras == null) return;

            Bundle extras = notification.extras;
            CharSequence titleSeq = extras.getCharSequence(Notification.EXTRA_TITLE);
            CharSequence textSeq = extras.getCharSequence(Notification.EXTRA_TEXT);

            String title = titleSeq != null ? titleSeq.toString() : "";
            String text = textSeq != null ? textSeq.toString() : "";
            String combined = (title + " " + text).trim();

            if (combined.isEmpty()) return;

            boolean hasLure = HIGH_RISK_LURE_PATTERN.matcher(combined).find();
            boolean hasUrl = URL_PATTERN.matcher(combined).find();

            if (hasLure || (hasUrl && isSuspiciousUrgentText(combined))) {
                Log.w(TAG, "Suspicious incoming message caught from " + packageName + ": " + combined);
                sendCitizenWarningNotification(packageName, title, combined);
            }

        } catch (Exception e) {
            Log.e(TAG, "Error inspecting notification: " + e.getMessage(), e);
        }
    }

    private boolean isSuspiciousUrgentText(String text) {
        String lower = text.toLowerCase();
        return lower.contains("urgent") || lower.contains("immediately") ||
                lower.contains("blocked") || lower.contains("disconnect") ||
                lower.contains("penalty") || lower.contains("reward") ||
                lower.contains("cashback");
    }

    private void sendCitizenWarningNotification(String sourcePackage, String sender, String scamText) {
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return;

        // Intent to launch Verity MainActivity and automatically scan the suspicious message
        Intent scanIntent = new Intent(this, MainActivity.class);
        scanIntent.setAction(Intent.ACTION_SEND);
        scanIntent.setType("text/plain");
        scanIntent.putExtra(Intent.EXTRA_TEXT, scamText);
        scanIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                (int) System.currentTimeMillis(),
                scanIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }

        builder.setContentTitle("🛡️ Verity Shield: Suspicious Message Detected")
                .setContentText("Potential scam from " + (sender.isEmpty() ? "incoming message" : sender) + ". Tap to verify safely.")
                .setStyle(new Notification.BigTextStyle().bigText(
                        "Potential scam detected: \"" + scamText + "\"\n\nDo not click links or pay. Tap here to inspect with Verity Shield."
                ))
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent);

        manager.notify((int) System.currentTimeMillis(), builder.build());
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Verity Security Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Alerts citizen when a high-risk scam or phishing SMS/WhatsApp message is received.");
            channel.enableVibration(true);

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
}
