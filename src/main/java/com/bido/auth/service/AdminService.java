package com.bido.auth.service;

import com.bido.auth.dto.AdminUserListDto;
import com.bido.auth.entity.enums.UserRole;
import com.bido.auth.mapper.UserMapper;
import com.bido.auth.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** Operațiile de citire ale panoului de admin. */
@Service
public class AdminService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public AdminService(UserRepository userRepository, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }

    /** Conturile pe care un admin le poate gestiona — toate mai puțin ceilalți admini. */
    @Transactional(readOnly = true)
    public List<AdminUserListDto> listManagedUsers() {
        return userRepository.findByRoleNotOrderByIdAsc(UserRole.ADMIN)
                .stream()
                .map(userMapper::toAdminDto)
                .toList();
    }
}
