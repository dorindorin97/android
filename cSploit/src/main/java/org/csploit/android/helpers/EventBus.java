/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * EventBus - Simple publish-subscribe event bus for decoupled communication.
 * 
 * Provides a lightweight event system for components to communicate without
 * direct dependencies. Supports both main thread and background delivery.
 * 
 * Usage:
 * {@code
 * // Subscribe
 * EventBus.getInstance().subscribe(NetworkEvent.class, event -> {
 *     // Handle event
 * });
 * 
 * // Publish
 * EventBus.getInstance().post(new NetworkEvent("connected"));
 * }
 */
public final class EventBus {
    
    private static final String TAG = "EventBus";
    
    private static volatile EventBus instance;
    
    private final Map<Class<?>, ConcurrentHashMap<Object, Subscriber<?>>> subscribers;
    private final Handler mainHandler;
    private final Map<String, Object> stickyEvents;
    
    /**
     * Event subscriber interface.
     * 
     * @param <T> Event type
     */
    public interface Subscriber<T> {
        void onEvent(@NonNull T event);
    }
    
    /**
     * Subscription options.
     */
    public enum ThreadMode {
        /** Deliver on the same thread as post */
        POSTING,
        /** Deliver on the main/UI thread */
        MAIN,
        /** Deliver on a background thread */
        BACKGROUND
    }
    
    /**
     * Get singleton instance.
     */
    @NonNull
    public static EventBus getInstance() {
        if (instance == null) {
            synchronized (EventBus.class) {
                if (instance == null) {
                    instance = new EventBus();
                }
            }
        }
        return instance;
    }
    
    private EventBus() {
        subscribers = new ConcurrentHashMap<>();
        mainHandler = new Handler(Looper.getMainLooper());
        stickyEvents = new ConcurrentHashMap<>();
    }
    
    /**
     * Subscribe to events of a specific type.
     * 
     * @param eventClass Event class to subscribe to
     * @param subscriber Event handler
     * @param <T> Event type
     * @return Subscription token for unsubscribing
     */
    @NonNull
    public <T> Object subscribe(@NonNull Class<T> eventClass, @NonNull Subscriber<T> subscriber) {
        return subscribe(eventClass, subscriber, ThreadMode.POSTING);
    }
    
    /**
     * Subscribe to events with specific thread mode.
     * 
     * @param eventClass Event class to subscribe to
     * @param subscriber Event handler
     * @param threadMode Thread delivery mode
     * @param <T> Event type
     * @return Subscription token for unsubscribing
     */
    @NonNull
    public <T> Object subscribe(@NonNull Class<T> eventClass, @NonNull Subscriber<T> subscriber,
                                 @NonNull ThreadMode threadMode) {
        ConcurrentHashMap<Object, Subscriber<?>> classSubscribers =
                subscribers.computeIfAbsent(eventClass, k -> new ConcurrentHashMap<>());
        
        SubscriptionWrapper<T> wrapper = new SubscriptionWrapper<>(subscriber, threadMode);
        Object token = new Object();
        classSubscribers.put(token, wrapper);
        
        // Deliver sticky event if exists
        Object stickyEvent = stickyEvents.get(eventClass.getName());
        if (stickyEvent != null && eventClass.isInstance(stickyEvent)) {
            deliverEvent(wrapper, eventClass.cast(stickyEvent));
        }
        
        return token;
    }
    
    /**
     * Unsubscribe using the subscription token.
     * 
     * @param token Subscription token returned from subscribe
     */
    public void unsubscribe(@NonNull Object token) {
        for (ConcurrentHashMap<Object, Subscriber<?>> classSubscribers : subscribers.values()) {
            classSubscribers.remove(token);
        }
    }
    
    /**
     * Unsubscribe all handlers for an event class.
     * 
     * @param eventClass Event class to unsubscribe from
     */
    public void unsubscribeAll(@NonNull Class<?> eventClass) {
        subscribers.remove(eventClass);
    }
    
    /**
     * Post an event to all subscribers.
     * 
     * @param event Event to post
     * @param <T> Event type
     */
    public <T> void post(@NonNull T event) {
        Class<?> eventClass = event.getClass();
        ConcurrentHashMap<Object, Subscriber<?>> classSubscribers = subscribers.get(eventClass);
        
        if (classSubscribers == null || classSubscribers.isEmpty()) {
            LoggingHelper.d(TAG, "No subscribers for event: " + eventClass.getSimpleName());
            return;
        }
        
        for (Subscriber<?> subscriber : classSubscribers.values()) {
            @SuppressWarnings("unchecked")
            SubscriptionWrapper<T> wrapper = (SubscriptionWrapper<T>) subscriber;
            deliverEvent(wrapper, event);
        }
    }
    
    /**
     * Post a sticky event that will be delivered to new subscribers.
     * 
     * @param event Event to post
     * @param <T> Event type
     */
    public <T> void postSticky(@NonNull T event) {
        stickyEvents.put(event.getClass().getName(), event);
        post(event);
    }
    
    /**
     * Remove a sticky event.
     * 
     * @param eventClass Event class to remove
     */
    public void removeStickyEvent(@NonNull Class<?> eventClass) {
        stickyEvents.remove(eventClass.getName());
    }
    
    /**
     * Get a sticky event if exists.
     * 
     * @param eventClass Event class
     * @param <T> Event type
     * @return Sticky event or null
     */
    @Nullable
    @SuppressWarnings("unchecked")
    public <T> T getStickyEvent(@NonNull Class<T> eventClass) {
        Object event = stickyEvents.get(eventClass.getName());
        return eventClass.isInstance(event) ? (T) event : null;
    }
    
    /**
     * Post an event with delay.
     * 
     * @param event Event to post
     * @param delayMs Delay in milliseconds
     * @param <T> Event type
     */
    public <T> void postDelayed(@NonNull T event, long delayMs) {
        mainHandler.postDelayed(() -> post(event), delayMs);
    }
    
    /**
     * Check if there are subscribers for an event.
     * 
     * @param eventClass Event class
     * @return true if has subscribers
     */
    public boolean hasSubscribers(@NonNull Class<?> eventClass) {
        ConcurrentHashMap<Object, Subscriber<?>> classSubscribers = subscribers.get(eventClass);
        return classSubscribers != null && !classSubscribers.isEmpty();
    }
    
    /**
     * Clear all subscriptions.
     */
    public void clear() {
        subscribers.clear();
        stickyEvents.clear();
    }
    
    private <T> void deliverEvent(@NonNull SubscriptionWrapper<T> wrapper, @NonNull T event) {
        switch (wrapper.threadMode) {
            case MAIN:
                if (Looper.myLooper() == Looper.getMainLooper()) {
                    wrapper.subscriber.onEvent(event);
                } else {
                    mainHandler.post(() -> wrapper.subscriber.onEvent(event));
                }
                break;
                
            case BACKGROUND:
                if (Looper.myLooper() != Looper.getMainLooper()) {
                    wrapper.subscriber.onEvent(event);
                } else {
                    ThreadHelper.getSharedExecutor().execute(() -> wrapper.subscriber.onEvent(event));
                }
                break;
                
            case POSTING:
            default:
                wrapper.subscriber.onEvent(event);
                break;
        }
    }
    
    private static class SubscriptionWrapper<T> implements Subscriber<T> {
        final Subscriber<T> subscriber;
        final ThreadMode threadMode;
        
        SubscriptionWrapper(Subscriber<T> subscriber, ThreadMode threadMode) {
            this.subscriber = subscriber;
            this.threadMode = threadMode;
        }
        
        @Override
        public void onEvent(@NonNull T event) {
            subscriber.onEvent(event);
        }
    }
    
    // Common event classes
    
    /**
     * Base event class with timestamp.
     */
    public static class BaseEvent {
        public final long timestamp;
        
        public BaseEvent() {
            this.timestamp = java.lang.System.currentTimeMillis();
        }
    }
    
    /**
     * Network state change event.
     */
    public static class NetworkStateEvent extends BaseEvent {
        public final boolean connected;
        public final String networkType;
        
        public NetworkStateEvent(boolean connected, String networkType) {
            this.connected = connected;
            this.networkType = networkType;
        }
    }
    
    /**
     * Target discovered event.
     */
    public static class TargetDiscoveredEvent extends BaseEvent {
        public final String ipAddress;
        public final String macAddress;
        public final String hostname;
        
        public TargetDiscoveredEvent(String ipAddress, String macAddress, String hostname) {
            this.ipAddress = ipAddress;
            this.macAddress = macAddress;
            this.hostname = hostname;
        }
    }
    
    /**
     * Scan progress event.
     */
    public static class ScanProgressEvent extends BaseEvent {
        public final int current;
        public final int total;
        public final String description;
        
        public ScanProgressEvent(int current, int total, String description) {
            this.current = current;
            this.total = total;
            this.description = description;
        }
        
        public int getProgressPercent() {
            return total > 0 ? (current * 100) / total : 0;
        }
    }
    
    /**
     * Scan completed event.
     */
    public static class ScanCompletedEvent extends BaseEvent {
        public final boolean success;
        public final int itemsFound;
        public final String message;
        
        public ScanCompletedEvent(boolean success, int itemsFound, String message) {
            this.success = success;
            this.itemsFound = itemsFound;
            this.message = message;
        }
    }
    
    /**
     * Error event.
     */
    public static class ErrorEvent extends BaseEvent {
        public final String message;
        public final Throwable cause;
        
        public ErrorEvent(String message) {
            this(message, null);
        }
        
        public ErrorEvent(String message, Throwable cause) {
            this.message = message;
            this.cause = cause;
        }
    }
    
    /**
     * Service state change event.
     */
    public static class ServiceStateEvent extends BaseEvent {
        public final String serviceName;
        public final boolean running;
        
        public ServiceStateEvent(String serviceName, boolean running) {
            this.serviceName = serviceName;
            this.running = running;
        }
    }
}
