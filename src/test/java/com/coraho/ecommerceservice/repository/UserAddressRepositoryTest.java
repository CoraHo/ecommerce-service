package com.coraho.ecommerceservice.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import com.coraho.ecommerceservice.entity.User;
import com.coraho.ecommerceservice.entity.UserAddress;
import com.coraho.ecommerceservice.entity.UserAddress.AddressType;

@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@DisplayName("UserAddressRepository Tests")
public class UserAddressRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserAddressRepository userAddressRepository;

    private User user;
    private UserAddress address1;
    private UserAddress address2;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .username("johndoe")
                .email("john@example.com")
                .passwordHash("secret")
                .build();
        entityManager.persistAndFlush(user);

        address1 = UserAddress.builder().user(user).isDefault(true)
                .addressType(AddressType.BILLING)
                .firstName("john")
                .lastName("doe")
                .addressLine1("123 Main St")
                .city("New York City")
                .country("United States")
                .postalCode("11022").build();
        entityManager.persistAndFlush(address1);

        address2 = UserAddress.builder().user(user).isDefault(false)
                .addressType(AddressType.BILLING)
                .firstName("john")
                .lastName("doe")
                .addressLine1("456 Side St")
                .city("New York City")
                .country("United States")
                .postalCode("22033")
                .build();
        entityManager.persistAndFlush(address2);
    }

    // --- findByUserId ---

    @Test
    void findByUserId_shouldReturnAllAddresses_whenUserHasAddresses() {
        List<UserAddress> result = userAddressRepository.findByUserId(user.getId());

        assertThat(result).hasSize(2);
    }

    @Test
    void findByUserId_shouldReturnEmpty_whenUserHasNoAddresses() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("Secret").build();

        entityManager.persistAndFlush(otherUser);

        List<UserAddress> result = userAddressRepository.findByUserId(otherUser.getId());

        assertThat(result).isEmpty();
    }

    // --- findByIdAndUserId ---

    @Test
    void findByIdAndUserId_shouldReturnAddress_whenAddressBelongsToUser() {
        Optional<UserAddress> result = userAddressRepository
                .findByIdAndUserId(address1.getId(), user.getId());

        assertThat(result).isPresent();
        assertThat(result.get().getAddressLine1()).isEqualTo("123 Main St");
    }

    @Test
    void findByIdAndUserId_shouldReturnEmpty_whenAddressDoesNotBelongToUser() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("Secret").build();

        entityManager.persistAndFlush(otherUser);

        Optional<UserAddress> result = userAddressRepository
                .findByIdAndUserId(address1.getId(), otherUser.getId());

        assertThat(result).isEmpty();
    }

    @Test
    void findByIdAndUserId_shouldReturnEmpty_whenAddressNotExists() {
        Optional<UserAddress> result = userAddressRepository
                .findByIdAndUserId(999L, user.getId());

        assertThat(result).isEmpty();
    }

    // --- clearDefaultAddresses ---

    @Test
    void clearDefaultAddresses_shouldSetAllAddressesToNonDefault() {
        userAddressRepository.clearDefaultAddresses(user.getId());
        entityManager.clear(); // force fresh fetch

        List<UserAddress> result = userAddressRepository.findByUserId(user.getId());

        assertThat(result).allMatch(a -> !a.getIsDefault());
    }

    @Test
    void clearDefaultAddresses_shouldNotAffectOtherUsers() {
        User otherUser = User.builder().username("janedoe")
                .email("jane@example.com").passwordHash("Secret").build();

        entityManager.persistAndFlush(otherUser);

        UserAddress otherAddress = UserAddress.builder().user(otherUser).isDefault(true)
                .addressType(AddressType.SHIPPING)
                .firstName("jane")
                .lastName("doe")
                .addressLine1("789 Other St")
                .city("New York City")
                .postalCode("33044")
                .country("United States").build();
        entityManager.persistAndFlush(otherAddress);

        userAddressRepository.clearDefaultAddresses(user.getId());
        entityManager.clear();

        Optional<UserAddress> result = userAddressRepository
                .findByIdAndUserId(otherAddress.getId(), otherUser.getId());

        assertThat(result).isPresent();
        assertThat(result.get().getIsDefault()).isTrue();
    }
}
