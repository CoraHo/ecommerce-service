package com.coraho.ecommerceservice.repository;

import com.coraho.ecommerceservice.entity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomerRepository extends JpaRepository<Customer, Long> {
    boolean existsById(Long id);

    Optional<Customer> findByEmail(String email);
}
