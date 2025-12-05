/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.example.sharding.jdbc.service;

import org.apache.shardingsphere.example.sharding.jdbc.entity.Address;
import org.apache.shardingsphere.example.sharding.jdbc.entity.Order;
import org.apache.shardingsphere.example.sharding.jdbc.entity.OrderItem;
import org.apache.shardingsphere.example.sharding.jdbc.repository.AddressRepository;
import org.apache.shardingsphere.example.sharding.jdbc.repository.OrderItemRepository;
import org.apache.shardingsphere.example.sharding.jdbc.repository.OrderRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public final class ExampleService {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(ExampleService.class);

    private DataSource dataSource;
    
    private final OrderRepository orderRepository;
    
    private final OrderItemRepository orderItemRepository;
    
    private final AddressRepository addressRepository;
    
    public ExampleService(final DataSource dataSource) {
        orderRepository = new OrderRepository(dataSource);
        orderItemRepository = new OrderItemRepository(dataSource);
        addressRepository = new AddressRepository(dataSource);
        this.dataSource = dataSource;
    }
    
    public void run() throws SQLException {
        try {
            this.initEnvironment();
            this.processSuccess();
        } finally {
            //this.cleanEnvironment();
        }
    }
    
    private void initEnvironment() throws SQLException {
        orderRepository.createTableIfNotExists();
        orderItemRepository.createTableIfNotExists();
        addressRepository.createTableIfNotExists();
        orderRepository.truncateTable();
        orderItemRepository.truncateTable();
        addressRepository.truncateTable();
    }
    
    private void processSuccess() throws SQLException {
        LOGGER.info("-------------- Process Success Begin ---------------");
        List<Long> orderIds = insertData();
        printData(); 
        //deleteData(orderIds);
        //printData();
        LOGGER.info("-------------- Process Success Finish --------------");
    }
    
    private List<Long> insertData() throws SQLException {
        LOGGER.info("---------------------------- Insert Data ----------------------------");
        List<Long> result = new ArrayList<>(10);
        for (int i = 1; i <= 10; i++) {
            Order order = new Order();
            order.setUserId(i);
            order.setOrderType(i % 2);
            order.setAddressId(i);
            order.setStatus("INSERT_TEST");
            orderRepository.insert(order);
            
            OrderItem orderItem = new OrderItem();
            orderItem.setOrderId(order.getOrderId());
            orderItem.setUserId(i);
            orderItem.setPhone("13800000001");
            orderItem.setStatus("INSERT_TEST");
            orderItemRepository.insert(orderItem);
            
            Address address = new Address();
            address.setAddressId((long) i);
            address.setAddressName("address_test_" + i);
            addressRepository.insert(address);
            
            result.add(order.getOrderId());
        }
        return result;
    }
    
    private void deleteData(final List<Long> orderIds) throws SQLException {
        LOGGER.info("---------------------------- Delete Data ----------------------------");
        long count = 1;
        for (Long each : orderIds) {
            orderRepository.delete(each);
            orderItemRepository.delete(each);
            addressRepository.delete(count++);
        }
    }
    
    private void printData() throws SQLException {
        LOGGER.info("---------------------------- Print Order Data -----------------------");
        for (Object each : this.selectAll()) {
            LOGGER.info(each.toString());
        }
        LOGGER.info("---------------------------- Print OrderItem Data -------------------");
        for (Object each : orderItemRepository.selectAll()) {
            LOGGER.info(each.toString());
        } 
        LOGGER.info("---------------------------- Print Address Data -------------------");
        for (Object each : addressRepository.selectAll()) {
            LOGGER.info(each.toString());
        }
        LOGGER.info("---------------------------- Print Union All Order Data ------------------------");
        for(Object each : this.selectUnionAll()) {
            LOGGER.info(each.toString());
        }
        LOGGER.info("---------------------------- Print LEFT JOIN Data ------------------------");
        for(Object each : this.selectJoin()) {
            LOGGER.info(each.toString());
        }
    }
    
    private List<Order> selectAll() throws SQLException {
        List<Order> result = orderRepository.selectAll();
        return result;
    }

    private List<Order> selectUnionAll() throws SQLException {
        String sql = "SELECT * FROM t_order UNION ALL SELECT * FROM t_order";
        List<Order> result = new LinkedList<>();
        try (Connection connection = dataSource.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(sql);
             ResultSet resultSet = preparedStatement.executeQuery()) {
            while (resultSet.next()) {
                Order order = new Order();
                order.setOrderId(resultSet.getLong(1));
                order.setOrderType(resultSet.getInt(2));
                order.setUserId(resultSet.getInt(3));
                order.setAddressId(resultSet.getLong(4));
                order.setStatus(resultSet.getString(5));
                result.add(order);
            }
        }
        return result;
    }

    private List<Order> selectJoin() throws SQLException {
        String sql = "select * from t_order left join t_order_item on t_order.user_id != t_order_item.user_id;";
        List<Order> result = new LinkedList<>();
        try (Connection connection = dataSource.getConnection();
            PreparedStatement preparedStatement = connection.prepareStatement(sql);
            ResultSet resultSet = preparedStatement.executeQuery()) {
            ResultSetMetaData resultSetMetaData = resultSet.getMetaData();
            for ( int i = 0; i < resultSetMetaData.getColumnCount(); i++) {
                String columnName = resultSetMetaData.getColumnName(i + 1);
                String columnType = resultSetMetaData.getColumnTypeName(i + 1);
                System.out.println(columnName + " " + columnType);
            }

            while (resultSet.next()) {
                String resultString =
                        resultSet.getLong(1) + " "
                      + resultSet.getInt(2) + " "
                      + resultSet.getInt(3) + " "
                      + resultSet.getLong(4) + " "
                      + resultSet.getString(5) + " "
                      + resultSet.getLong(6) + " "
                      + resultSet.getLong(7) + " "
                      + resultSet.getInt(8) + " "
                      + resultSet.getString(9) + " "
                      + resultSet.getString(10);
                System.out.println(resultString);
            }
        }
        return result;
    }
    
    private void cleanEnvironment() throws SQLException {
        orderRepository.dropTable();
        orderItemRepository.dropTable();
        addressRepository.dropTable();
    }
}
