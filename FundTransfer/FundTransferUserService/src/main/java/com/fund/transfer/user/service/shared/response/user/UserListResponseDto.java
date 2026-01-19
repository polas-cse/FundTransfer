package com.fund.transfer.user.service.shared.response.user;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserListResponseDto {

    private Long createdBy;

}
