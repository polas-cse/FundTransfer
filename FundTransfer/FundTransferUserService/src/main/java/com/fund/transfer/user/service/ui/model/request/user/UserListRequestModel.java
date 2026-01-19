package com.fund.transfer.user.service.ui.model.request.user;

import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(callSuper=false)
public class UserListRequestModel {

    private Long createdBy;

}
