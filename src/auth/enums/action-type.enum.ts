export enum ActionType {
  // User-related actions
  USER_REGISTER = 'USER_REGISTER',
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  USER_UPDATE_PROFILE = 'USER_UPDATE_PROFILE',
  USER_CHANGE_PASSWORD = 'USER_CHANGE_PASSWORD',
  USER_DELETE_ACCOUNT = 'USER_DELETE_ACCOUNT',

  // Product-related actions
  PRODUCT_CREATE = 'PRODUCT_CREATE',
  PRODUCT_UPDATE = 'PRODUCT_UPDATE',
  PRODUCT_DELETE = 'PRODUCT_DELETE',
  PRODUCT_VIEW = 'PRODUCT_VIEW',
  PRODUCT_SEARCH = 'PRODUCT_SEARCH',
  PRODUCT_WISHLIST = 'PRODUCT_WISHLIST',
  PRODUCT_REMOVE_WISHLIST = 'PRODUCT_REMOVE_WISHLIST',

  // Order-related actions
  ORDER_CREATE = 'ORDER_CREATE',
  ORDER_UPDATE = 'ORDER_UPDATE',
  ORDER_CANCEL = 'ORDER_CANCEL',
  ORDER_COMPLETE = 'ORDER_COMPLETE',
  ORDER_REFUND_REQUEST = 'ORDER_REFUND_REQUEST',

  // Review-related actions
  REVIEW_ADD = 'REVIEW_ADD',
  REVIEW_UPDATE = 'REVIEW_UPDATE',
  REVIEW_DELETE = 'REVIEW_DELETE',

  // Admin-related actions
  ADMIN_DELETE_USER = 'ADMIN_DELETE_USER',
  ADMIN_SUSPEND_USER = 'ADMIN_SUSPEND_USER',
  ADMIN_ACTIVATE_USER = 'ADMIN_ACTIVATE_USER',
  ADMIN_UPDATE_USER_ROLE = 'ADMIN_UPDATE_USER_ROLE',

  // Notification-related actions
  NOTIFICATION_SEND = 'NOTIFICATION_SEND',
  NOTIFICATION_READ = 'NOTIFICATION_READ',

  // Coupon-related actions
  COUPON_CREATE = 'COUPON_CREATE',
  COUPON_UPDATE = 'COUPON_UPDATE',
  COUPON_DELETE = 'COUPON_DELETE',
  COUPON_REDEEM = 'COUPON_REDEEM',

  // Payment-related actions
  PAYMENT_SUCCESS = 'PAYMENT_SUCCESS',
  PAYMENT_FAILURE = 'PAYMENT_FAILURE',
  PAYMENT_REFUND = 'PAYMENT_REFUND',
}
