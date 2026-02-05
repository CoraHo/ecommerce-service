package com.coraho.ecommerceservice.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.coraho.ecommerceservice.entity.UserAddress;

@Repository
public interface UserAddressRepository extends JpaRepository<UserAddress, Long> {

    List<UserAddress> findByUserId(Long userId);

    @Modifying
    @Query("""
            UPDATE UserAddress ua
            SET ua.isDefault = false
            WHERE ua.user.id = :userId
            """)
    void clearDefaultAddresses(@Param("userId") Long userId);

}
