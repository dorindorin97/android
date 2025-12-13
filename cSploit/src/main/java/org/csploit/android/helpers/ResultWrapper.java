package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

/**
 * A generic result wrapper that represents either a success value or an error.
 * Useful for handling operations that can fail without using exceptions.
 *
 * @param <T> The type of the success value
 * @param <E> The type of the error (typically String or Throwable)
 */
public class ResultWrapper<T, E> {

    @Nullable
    private final T value;
    @Nullable
    private final E error;
    private final boolean success;

    private ResultWrapper(@Nullable T value, @Nullable E error, boolean success) {
        this.value = value;
        this.error = error;
        this.success = success;
    }

    /**
     * Create a successful result with the given value.
     *
     * @param value The success value
     * @param <T>   The type of the value
     * @param <E>   The type of potential error
     * @return A success result
     */
    @NonNull
    public static <T, E> ResultWrapper<T, E> success(@Nullable T value) {
        return new ResultWrapper<>(value, null, true);
    }

    /**
     * Create a failed result with the given error.
     *
     * @param error The error
     * @param <T>   The type of potential value
     * @param <E>   The type of the error
     * @return A failure result
     */
    @NonNull
    public static <T, E> ResultWrapper<T, E> failure(@NonNull E error) {
        return new ResultWrapper<>(null, error, false);
    }

    /**
     * Create a result from a nullable value and error message for null values.
     *
     * @param value        The potentially null value
     * @param errorMessage Error message if value is null
     * @param <T>          The type of the value
     * @return Success if value is non-null, failure otherwise
     */
    @NonNull
    public static <T> ResultWrapper<T, String> ofNullable(@Nullable T value, @NonNull String errorMessage) {
        if (value != null) {
            return success(value);
        }
        return failure(errorMessage);
    }

    /**
     * Create a result from a callable operation that might throw.
     *
     * @param operation The operation to execute
     * @param <T>       The return type
     * @return Success with value or failure with exception
     */
    @NonNull
    public static <T> ResultWrapper<T, Throwable> fromOperation(@NonNull ThrowingSupplier<T> operation) {
        try {
            return success(operation.get());
        } catch (Throwable e) {
            return failure(e);
        }
    }

    /**
     * Check if this is a success result.
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Check if this is a failure result.
     */
    public boolean isFailure() {
        return !success;
    }

    /**
     * Get the success value.
     *
     * @return The value, or null if this is a failure
     */
    @Nullable
    public T getValue() {
        return value;
    }

    /**
     * Get the success value or a default if this is a failure.
     *
     * @param defaultValue The default value to return on failure
     * @return The value or the default
     */
    @Nullable
    public T getOrDefault(@Nullable T defaultValue) {
        return success ? value : defaultValue;
    }

    /**
     * Get the success value or throw an exception if this is a failure.
     *
     * @return The value
     * @throws IllegalStateException if this is a failure result
     */
    @Nullable
    public T getOrThrow() {
        if (!success) {
            throw new IllegalStateException("Cannot get value from failure result: " + error);
        }
        return value;
    }

    /**
     * Get the error.
     *
     * @return The error, or null if this is a success
     */
    @Nullable
    public E getError() {
        return error;
    }

    /**
     * Execute an action if this is a success.
     *
     * @param action The action to execute with the value
     * @return This result for chaining
     */
    @NonNull
    public ResultWrapper<T, E> onSuccess(@NonNull Consumer<T> action) {
        if (success) {
            action.accept(value);
        }
        return this;
    }

    /**
     * Execute an action if this is a failure.
     *
     * @param action The action to execute with the error
     * @return This result for chaining
     */
    @NonNull
    public ResultWrapper<T, E> onFailure(@NonNull Consumer<E> action) {
        if (!success) {
            action.accept(error);
        }
        return this;
    }

    /**
     * Transform the success value.
     *
     * @param mapper The transformation function
     * @param <U>    The new value type
     * @return A new result with transformed value, or the same failure
     */
    @NonNull
    public <U> ResultWrapper<U, E> map(@NonNull Function<T, U> mapper) {
        if (success) {
            return success(mapper.apply(value));
        }
        return failure(error);
    }

    /**
     * Transform and flatten the result.
     *
     * @param mapper The transformation function returning a Result
     * @param <U>    The new value type
     * @return The transformed result
     */
    @NonNull
    public <U> ResultWrapper<U, E> flatMap(@NonNull Function<T, ResultWrapper<U, E>> mapper) {
        if (success) {
            return mapper.apply(value);
        }
        return failure(error);
    }

    /**
     * Transform the error.
     *
     * @param mapper The error transformation function
     * @param <F>    The new error type
     * @return A new result with transformed error, or the same success
     */
    @NonNull
    public <F> ResultWrapper<T, F> mapError(@NonNull Function<E, F> mapper) {
        if (!success) {
            return failure(mapper.apply(error));
        }
        return success(value);
    }

    /**
     * Recover from a failure by providing an alternative value.
     *
     * @param recovery The recovery function
     * @return A success result with either the original or recovered value
     */
    @NonNull
    public ResultWrapper<T, E> recover(@NonNull Function<E, T> recovery) {
        if (!success) {
            return success(recovery.apply(error));
        }
        return this;
    }

    /**
     * Fold the result into a single value.
     *
     * @param onSuccess Function to apply on success
     * @param onFailure Function to apply on failure
     * @param <R>       The result type
     * @return The folded value
     */
    public <R> R fold(@NonNull Function<T, R> onSuccess, @NonNull Function<E, R> onFailure) {
        if (success) {
            return onSuccess.apply(value);
        }
        return onFailure.apply(error);
    }

    @Override
    public String toString() {
        if (success) {
            return "Success(" + value + ")";
        }
        return "Failure(" + error + ")";
    }

    // Functional interfaces for Java 7 compatibility

    /**
     * A supplier that can throw exceptions.
     */
    public interface ThrowingSupplier<T> {
        T get() throws Throwable;
    }

    /**
     * A consumer functional interface.
     */
    public interface Consumer<T> {
        void accept(T value);
    }

    /**
     * A function functional interface.
     */
    public interface Function<T, R> {
        R apply(T value);
    }

    // Convenience static methods for common string error cases

    /**
     * Create a result for network operations.
     */
    @NonNull
    public static <T> ResultWrapper<T, String> networkError(@NonNull String message) {
        return failure("Network error: " + message);
    }

    /**
     * Create a result for validation errors.
     */
    @NonNull
    public static <T> ResultWrapper<T, String> validationError(@NonNull String message) {
        return failure("Validation error: " + message);
    }

    /**
     * Create a result for timeout errors.
     */
    @NonNull
    public static <T> ResultWrapper<T, String> timeoutError(@NonNull String operation) {
        return failure("Timeout: " + operation);
    }

    /**
     * Create a result for permission errors.
     */
    @NonNull
    public static <T> ResultWrapper<T, String> permissionError(@NonNull String permission) {
        return failure("Permission denied: " + permission);
    }

    /**
     * Create a result for not found errors.
     */
    @NonNull
    public static <T> ResultWrapper<T, String> notFoundError(@NonNull String resource) {
        return failure("Not found: " + resource);
    }
}
