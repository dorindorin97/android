package org.csploit.android.core;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.csploit.android.events.Event;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages event publishing and subscription.
 * Extracted from System.java to improve separation of concerns.
 * Provides a simple pub-sub mechanism for decoupled component communication.
 */
public class EventManager {
    private static final String TAG = "EventManager";

    private final Map<Class<?>, List<EventListener<?>>> listeners;
    private final List<EventInterceptor> interceptors;

    /**
     * Listener interface for events.
     *
     * @param <T> The event type
     */
    public interface EventListener<T extends Event> {
        void onEvent(@NonNull T event);
    }

    /**
     * Interceptor interface for preprocessing events.
     */
    public interface EventInterceptor {
        boolean shouldProcess(@NonNull Event event);
    }

    public EventManager() {
        this.listeners = Collections.synchronizedMap(new HashMap<>());
        this.interceptors = new CopyOnWriteArrayList<>();
    }

    /**
     * Subscribe to events of a specific type.
     *
     * @param eventType The event class to listen for
     * @param listener The listener callback
     * @param <T> The event type
     */
    public <T extends Event> void subscribe(@NonNull Class<T> eventType, @NonNull EventListener<T> listener) {
        if (eventType == null || listener == null) {
            throw new IllegalArgumentException("Event type and listener cannot be null");
        }

        List<EventListener<?>> eventListeners = listeners.computeIfAbsent(
                eventType,
                k -> new CopyOnWriteArrayList<>()
        );

        eventListeners.add(listener);
        Log.d(TAG, "Subscriber added for " + eventType.getSimpleName());
    }

    /**
     * Unsubscribe from events of a specific type.
     *
     * @param eventType The event class to stop listening for
     * @param listener The listener callback to remove
     * @param <T> The event type
     * @return true if listener was removed, false otherwise
     */
    public <T extends Event> boolean unsubscribe(@NonNull Class<T> eventType, @NonNull EventListener<T> listener) {
        List<EventListener<?>> eventListeners = listeners.get(eventType);
        if (eventListeners == null) {
            return false;
        }

        boolean removed = eventListeners.remove(listener);
        if (removed) {
            Log.d(TAG, "Subscriber removed for " + eventType.getSimpleName());
            if (eventListeners.isEmpty()) {
                listeners.remove(eventType);
            }
        }
        return removed;
    }

    /**
     * Publish an event to all subscribers.
     *
     * @param event The event to publish
     */
    public void publish(@NonNull Event event) {
        if (event == null) {
            throw new IllegalArgumentException("Event cannot be null");
        }

        // Check interceptors
        for (EventInterceptor interceptor : interceptors) {
            if (!interceptor.shouldProcess(event)) {
                Log.d(TAG, "Event intercepted: " + event.getClass().getSimpleName());
                return;
            }
        }

        Class<?> eventType = event.getClass();
        List<EventListener<?>> eventListeners = listeners.get(eventType);

        if (eventListeners != null && !eventListeners.isEmpty()) {
            Log.d(TAG, "Publishing event: " + eventType.getSimpleName() + " to " + eventListeners.size() + " listeners");
            for (EventListener<?> listener : eventListeners) {
                try {
                    notifyListener(listener, event);
                } catch (Exception e) {
                    Log.e(TAG, "Error notifying listener for " + eventType.getSimpleName(), e);
                }
            }
        } else {
            Log.d(TAG, "No listeners registered for event: " + eventType.getSimpleName());
        }
    }

    /**
     * Check if any listeners are registered for an event type.
     *
     * @param eventType The event class to check
     * @return true if listeners exist, false otherwise
     */
    public boolean hasListeners(@NonNull Class<?> eventType) {
        List<EventListener<?>> list = listeners.get(eventType);
        return list != null && !list.isEmpty();
    }

    /**
     * Get listener count for an event type.
     *
     * @param eventType The event class to check
     * @return Number of registered listeners
     */
    public int getListenerCount(@NonNull Class<?> eventType) {
        List<EventListener<?>> eventListeners = listeners.get(eventType);
        return eventListeners != null ? eventListeners.size() : 0;
    }

    /**
     * Add an event interceptor.
     *
     * @param interceptor The interceptor to add
     */
    public void addInterceptor(@NonNull EventInterceptor interceptor) {
        if (interceptor == null) {
            throw new IllegalArgumentException("Interceptor cannot be null");
        }
        interceptors.add(interceptor);
        Log.d(TAG, "Event interceptor added");
    }

    /**
     * Remove an event interceptor.
     *
     * @param interceptor The interceptor to remove
     * @return true if interceptor was removed, false otherwise
     */
    public boolean removeInterceptor(@NonNull EventInterceptor interceptor) {
        boolean removed = interceptors.remove(interceptor);
        if (removed) {
            Log.d(TAG, "Event interceptor removed");
        }
        return removed;
    }

    /**
     * Clear all listeners for a specific event type.
     *
     * @param eventType The event class to clear
     */
    public void clearListeners(@NonNull Class<?> eventType) {
        listeners.remove(eventType);
        Log.d(TAG, "Listeners cleared for " + eventType.getSimpleName());
    }

    /**
     * Clear all listeners and interceptors.
     */
    public void clearAll() {
        listeners.clear();
        interceptors.clear();
        Log.d(TAG, "All listeners and interceptors cleared");
    }

    /**
     * Get total count of registered listeners across all event types.
     *
     * @return Total listener count
     */
    public int getTotalListenerCount() {
        return listeners.values()
                .stream()
                .mapToInt(List::size)
                .sum();
    }

    /**
     * Notify a listener about an event (with type safety).
     *
     * @param listener The listener
     * @param event The event
     */
    @SuppressWarnings("unchecked")
    private void notifyListener(EventListener<?> listener, Event event) {
        ((EventListener<Event>) listener).onEvent(event);
    }

    /**
     * Get status summary.
     *
     * @return A string describing the current state
     */
    @NonNull
    public String getStatusSummary() {
        return String.format(
                "EventManager [Event types: %d, Total listeners: %d, Interceptors: %d]",
                listeners.size(),
                getTotalListenerCount(),
                interceptors.size()
        );
    }
}
