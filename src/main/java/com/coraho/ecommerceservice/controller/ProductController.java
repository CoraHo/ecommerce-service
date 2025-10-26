package com.coraho.ecommerceservice.controller;

import com.coraho.ecommerceservice.entity.Product;
import com.coraho.ecommerceservice.service.ProductService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/products")
public class ProductController {

    private final ProductService productService;

    public ProductController(ProductService productService) {
        this.productService = productService;
    }

    @GetMapping
    public ResponseEntity<List<Product>> getAllProducts() {
        List<Product> allProducts = productService.findAllProducts();
        return ResponseEntity.ok(allProducts);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Product> getProductByID(@PathVariable Long id) {
        Product product = productService.findByID(id);
        return ResponseEntity.ok(product);
    }

    @PostMapping
    public ResponseEntity<Product> addProduct(@RequestBody Product product) {
        return ResponseEntity.ok(productService.addProduct(product));
    }

    @DeleteMapping("/{sku}")
    public ResponseEntity<String> deleteProductBySKU(@PathVariable String sku) {
        productService.deleteProductBySKU(sku);
        return ResponseEntity.ok("Product with SKU: " + sku + " has been deleted");
    }

    @PutMapping("/{sku}")
    public ResponseEntity<Product> updateProduct(@PathVariable String sku, @RequestBody Product product) {
        return ResponseEntity.ok(productService.updateProduct(sku, product));
    }

}
