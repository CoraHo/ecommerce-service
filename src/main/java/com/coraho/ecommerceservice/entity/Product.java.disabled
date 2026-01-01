package com.coraho.ecommerceservice.entity;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "products")
@Entity
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String sku;

    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(nullable = false)
    private Double price;

    @Column(length = 255)
    private String description;

    @Column(name = "image_url", length = 512)
    private String imageUrl;

    @Column(nullable = false, name = "stock_qty")
    private Integer stockQuantity;

    private String category;

}
