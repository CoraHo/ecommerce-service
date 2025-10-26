package com.coraho.ecommerceservice.service;

import com.coraho.ecommerceservice.entity.Product;
import com.coraho.ecommerceservice.repository.ProductRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
@Transactional
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> findAllProducts(){
        return productRepository.findAll();
    }

    public Product findByID(Long id) {
        return productRepository.findById(id).orElseThrow(() -> new RuntimeException("Product not found by ID: " + id));
    }

    public boolean existsBySKU(String sku) {
        return productRepository.existsBySku(sku);
    }

    public List<Product> findByCategoryIgnoreCase(String category){
        return productRepository.findByCategoryIgnoreCase(category);
    }

    public Product findBySKU(String sku) {
        return productRepository.findBySku(sku).orElseThrow(() -> new RuntimeException("Product not found by SKU: " + sku));
    }

    public Product addProduct(Product product) {
        if (existsBySKU(product.getSku())){
            throw new RuntimeException("SKU already exists: " + product.getSku());
        }
        return productRepository.save(product);
    }

    public void deleteProductBySKU(String sku) {
        Product product = findBySKU(sku);
        productRepository.delete(product);
    }

    public Product updateProduct(String sku, Product newProduct) {
        Product existing = findBySKU(sku);

        existing.setName(newProduct.getName());
        existing.setDescription(newProduct.getDescription());
        existing.setPrice(newProduct.getPrice());
        existing.setImageUrl(newProduct.getImageUrl());
        existing.setStockQuantity(newProduct.getStockQuantity());
        existing.setCategory(newProduct.getCategory());

        return productRepository.save(existing);
    }

}
