package com.fund.transfer.user.service.shared.request.user;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserListRequestDto {

    private Long createdBy;
    private Integer limit;
    private Integer offset;
    private String search;

}
