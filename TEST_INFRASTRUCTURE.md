# Test Infrastructure Guide

This document describes the testing framework and how to write tests for cSploit.

## Overview

cSploit now includes comprehensive testing infrastructure with:
- **Unit Testing**: JUnit5 with JUnit4 backward compatibility
- **Mocking**: Mockito for object mocking
- **Assertions**: AssertJ for fluent assertions
- **Android Testing**: Espresso for UI tests
- **Context Testing**: Robolectric for tests requiring Android context

## Dependencies Added

### Unit Testing
- `junit:junit:4.13.2` - Classic JUnit 4
- `org.junit.jupiter:junit-jupiter-api:5.9.2` - JUnit5 API
- `org.junit.jupiter:junit-jupiter-engine:5.9.2` - JUnit5 Engine
- `org.junit.vintage:junit-vintage-engine:5.9.2` - JUnit4 compatibility

### Mocking
- `org.mockito:mockito-core:5.2.0` - Core mocking framework
- `org.mockito:mockito-inline:5.2.0` - For mocking static methods
- `org.mockito:mockito-android:5.2.0` - Android-specific mocking

### Assertions
- `org.assertj:assertj-core:3.24.1` - Fluent assertions

### Android Testing
- `androidx.test.ext:junit:1.1.5` - AndroidX test extensions
- `androidx.test.espresso:espresso-core:3.5.1` - UI testing
- `androidx.test:runner:1.5.2` - Test runner
- `androidx.test:rules:1.5.0` - Test rules

### Context Testing
- `org.robolectric:robolectric:4.10` - Android framework simulation

## Running Tests

### Run all unit tests
```bash
./gradlew test
```

### Run specific test class
```bash
./gradlew test --tests org.csploit.android.core.SessionManagerTest
```

### Run Android instrumented tests
```bash
./gradlew connectedAndroidTest
```

### Run with coverage report
```bash
./gradlew test jacocoTestReport
```

## Writing Unit Tests

### Example: Basic Unit Test with JUnit5

```java
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

public class MyClassTest {

    private MyClass objectUnderTest;

    @BeforeEach
    void setUp() {
        objectUnderTest = new MyClass();
    }

    @Test
    void testSomeFeature() {
        String result = objectUnderTest.doSomething();
        assertThat(result).isEqualTo("expected");
    }
}
```

### Example: Test with Mocking

```java
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import static org.mockito.Mockito.*;

public class ServiceTest {

    @Mock
    private Dependency dependency;

    private Service service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new Service(dependency);
    }

    @Test
    void testWithMockedDependency() {
        when(dependency.getValue()).thenReturn("mocked");

        String result = service.process();

        assertThat(result).isNotNull();
        verify(dependency).getValue();
    }
}
```

### Example: Test with Android Context (using Robolectric)

```java
import org.robolectric.RobolectricTestRunner;
import androidx.test.core.app.ApplicationProvider;
import android.content.Context;

@RunWith(RobolectricTestRunner.class)
public class AndroidComponentTest {

    private Context context;

    @Before
    public void setUp() {
        context = ApplicationProvider.getApplicationContext();
    }

    @Test
    public void testWithContext() {
        // Test code that requires Android context
        assertThat(context).isNotNull();
    }
}
```

## Test Organization

### Directory Structure
```
cSploit/src/
├── main/
│   └── java/org/csploit/android/
│       ├── core/
│       ├── helpers/
│       ├── plugins/
│       └── ...
├── test/
│   └── java/org/csploit/android/
│       ├── core/
│       ├── helpers/
│       └── ...
└── androidTest/
    └── java/org/csploit/android/
        ├── ui/
        └── integration/
```

### Naming Conventions
- Unit test files: `{ClassName}Test.java`
- Integration test files: `{ClassName}IntegrationTest.java`
- Android instrumented tests: `{ClassName}AndroidTest.java`

## Best Practices

### 1. Test One Thing
Each test should focus on a single behavior:
```java
@Test
void testCalculateSum() {
    int result = calculator.add(2, 3);
    assertThat(result).isEqualTo(5);
}
```

### 2. Use Descriptive Names
Test names should clearly describe what is being tested:
```java
@Test
void shouldThrowExceptionWhenInputIsNull() { ... }

@Test
void shouldReturnEmptyListWhenNoItemsExist() { ... }
```

### 3. Use Arrange-Act-Assert Pattern
```java
@Test
void testUserCreation() {
    // Arrange
    User user = new User("John", "john@example.com");

    // Act
    boolean isValid = user.validate();

    // Assert
    assertThat(isValid).isTrue();
}
```

### 4. Mock External Dependencies
```java
@Test
void testProcessing(@Mock ExternalService service) {
    when(service.fetch()).thenReturn("data");

    // Your test code

    verify(service).fetch();
}
```

### 5. Test Edge Cases
```java
@Test
void shouldHandleNullInput() {
    assertThatThrownBy(() -> method(null))
        .isInstanceOf(NullPointerException.class);
}

@Test
void shouldHandleEmptyList() {
    List<String> empty = Collections.emptyList();
    assertThat(processList(empty)).isEmpty();
}
```

## Classes Ready for Testing

The following newly created classes have been designed with testing in mind:

1. **SessionManager** - Session persistence operations
   - Test file: `SessionManagerTest.java`
   - Can be tested independently without Android context

2. **ErrorLogger** - Error logging functionality
   - Test file: `ErrorLoggerTest.java`
   - Can be tested with temporary directories (JUnit5 @TempDir)

3. **NetworkConfig** - Network configuration management
   - Pure POJO, easy to test
   - No external dependencies

4. **ThreadPoolManager** - Thread pool management
   - Thread-safe, can be tested with CountDownLatch
   - Good candidate for concurrency testing

5. **SafeThreadHelper** - Safe thread operations
   - Utility methods, easy to unit test
   - Can test interruption handling

## Continuous Improvement

As development continues, add tests for:
- Critical business logic
- Edge cases and error conditions
- Integration points between components
- Network operations (use mocking)
- Database operations (use test doubles)

## Resources

- [JUnit5 Documentation](https://junit.org/junit5/docs/current/user-guide/)
- [Mockito Documentation](https://javadoc.io/doc/org.mockito/mockito-core/latest/org/mockito/Mockito.html)
- [AssertJ Assertions](https://assertj.github.io/assertj-core-features-highlight)
- [Espresso Testing Guide](https://developer.android.com/training/testing/espresso)
- [Robolectric Documentation](http://robolectric.org/)
