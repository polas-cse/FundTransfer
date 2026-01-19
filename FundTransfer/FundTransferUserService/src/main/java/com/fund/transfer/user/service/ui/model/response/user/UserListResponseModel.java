package com.fund.transfer.user.service.ui.model.response.user;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserListResponseModel {

    private Long createdBy;

}
