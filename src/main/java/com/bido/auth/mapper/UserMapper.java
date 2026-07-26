package com.bido.auth.mapper;

import com.bido.auth.dto.AdminUserListDto;
import com.bido.auth.entity.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    public AdminUserListDto toAdminDto(User user) {
        return new AdminUserListDto(
                user.getId(),
                user.getEmail(),
                user.getRole(),
                user.isSuspended(),
                user.getCreatedAt(),
                user.getLastLoginAt()
        );
    }
}
