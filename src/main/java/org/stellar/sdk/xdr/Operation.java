// Automatically generated by xdrgen 
// DO NOT EDIT or your changes may be overwritten

package org.stellar.sdk.xdr;


import java.io.IOException;

// === xdr source ============================================================

//  struct Operation
//  {
//      // sourceAccount is the account used to run the operation
//      // if not set, the runtime defaults to "sourceAccount" specified at
//      // the transaction level
//      AccountID* sourceAccount;
//  
//      union switch (OperationType type)
//      {
//      case CREATE_ACCOUNT:
//          CreateAccountOp createAccountOp;
//      case PAYMENT:
//          PaymentOp paymentOp;
//      case PATH_PAYMENT:
//          PathPaymentOp pathPaymentOp;
//      case MANAGE_OFFER:
//          ManageOfferOp manageOfferOp;
//      case CREATE_PASSIVE_OFFER:
//          CreatePassiveOfferOp createPassiveOfferOp;
//      case SET_OPTIONS:
//          SetOptionsOp setOptionsOp;
//      case CHANGE_TRUST:
//          ChangeTrustOp changeTrustOp;
//      case ALLOW_TRUST:
//          AllowTrustOp allowTrustOp;
//      case ACCOUNT_MERGE:
//          AccountID destination;
//      case INFLATION:
//          void;
//      case MANAGE_DATA:
//          ManageDataOp manageDataOp;
//      case BUMP_SEQUENCE:
//          BumpSequenceOp bumpSequenceOp;
//      }
//      body;
//  };

//  ===========================================================================
public class Operation  {
  public Operation () {}
  private AccountID sourceAccount;
  public AccountID getSourceAccount() {
    return this.sourceAccount;
  }
  public void setSourceAccount(AccountID value) {
    this.sourceAccount = value;
  }
  private OperationBody body;
  public OperationBody getBody() {
    return this.body;
  }
  public void setBody(OperationBody value) {
    this.body = value;
  }
  public static void encode(XdrDataOutputStream stream, Operation encodedOperation) throws IOException{
    if (encodedOperation.sourceAccount != null) {
    stream.writeInt(1);
    AccountID.encode(stream, encodedOperation.sourceAccount);
    } else {
    stream.writeInt(0);
    }
    //OperationBody.encode(stream, encodedOperation.body);
    OperationBody.encodeForTestOnly(stream, encodedOperation.body);
  }
  public static Operation decode(XdrDataInputStream stream) throws IOException {
    Operation decodedOperation = new Operation();
    int sourceAccountPresent = stream.readInt();
    if (sourceAccountPresent != 0) {
    decodedOperation.sourceAccount = AccountID.decode(stream);
    }
    decodedOperation.body = OperationBody.decode(stream);
    return decodedOperation;
  }

  public static class OperationBody {
    public OperationBody () {}
    OperationType type;
    public OperationType getDiscriminant() {
      return this.type;
    }
    public void setDiscriminant(OperationType value) {
      this.type = value;
    }
    private CreateAccountOp createAccountOp;
    public CreateAccountOp getCreateAccountOp() {
      return this.createAccountOp;
    }
    public void setCreateAccountOp(CreateAccountOp value) {
      this.createAccountOp = value;
    }
    private PaymentOp paymentOp;
    public PaymentOp getPaymentOp() {
      return this.paymentOp;
    }
    public void setPaymentOp(PaymentOp value) {
      this.paymentOp = value;
    }
    private PathPaymentOp pathPaymentOp;
    public PathPaymentOp getPathPaymentOp() {
      return this.pathPaymentOp;
    }
    public void setPathPaymentOp(PathPaymentOp value) {
      this.pathPaymentOp = value;
    }
    private ManageOfferOp manageOfferOp;
    public ManageOfferOp getManageOfferOp() {
      return this.manageOfferOp;
    }
    public void setManageOfferOp(ManageOfferOp value) {
      this.manageOfferOp = value;
    }
    private CreatePassiveOfferOp createPassiveOfferOp;
    public CreatePassiveOfferOp getCreatePassiveOfferOp() {
      return this.createPassiveOfferOp;
    }
    public void setCreatePassiveOfferOp(CreatePassiveOfferOp value) {
      this.createPassiveOfferOp = value;
    }
    private SetOptionsOp setOptionsOp;
    public SetOptionsOp getSetOptionsOp() {
      return this.setOptionsOp;
    }
    public void setSetOptionsOp(SetOptionsOp value) {
      this.setOptionsOp = value;
    }
    private ChangeTrustOp changeTrustOp;
    public ChangeTrustOp getChangeTrustOp() {
      return this.changeTrustOp;
    }
    public void setChangeTrustOp(ChangeTrustOp value) {
      this.changeTrustOp = value;
    }
    private AllowTrustOp allowTrustOp;
    public AllowTrustOp getAllowTrustOp() {
      return this.allowTrustOp;
    }
    public void setAllowTrustOp(AllowTrustOp value) {
      this.allowTrustOp = value;
    }
    private AccountID destination;
    public AccountID getDestination() {
      return this.destination;
    }
    public void setDestination(AccountID value) {
      this.destination = value;
    }
    private ManageDataOp manageDataOp;
    public ManageDataOp getManageDataOp() {
      return this.manageDataOp;
    }
    public void setManageDataOp(ManageDataOp value) {
      this.manageDataOp = value;
    }
    private BumpSequenceOp bumpSequenceOp;
    public BumpSequenceOp getBumpSequenceOp() {
      return this.bumpSequenceOp;
    }
    public void setBumpSequenceOp(BumpSequenceOp value) {
      this.bumpSequenceOp = value;
    }
    public static void encode(XdrDataOutputStream stream, OperationBody encodedOperationBody) throws IOException {
    stream.writeInt(encodedOperationBody.getDiscriminant().getValue());
    switch (encodedOperationBody.getDiscriminant()) {
    case CREATE_ACCOUNT:
    CreateAccountOp.encode(stream, encodedOperationBody.createAccountOp);
    break;
    case PAYMENT:
    PaymentOp.encode(stream, encodedOperationBody.paymentOp);
    break;
    case PATH_PAYMENT:
    PathPaymentOp.encode(stream, encodedOperationBody.pathPaymentOp);
    break;
    case MANAGE_OFFER:
    ManageOfferOp.encode(stream, encodedOperationBody.manageOfferOp);
    break;
    case CREATE_PASSIVE_OFFER:
    CreatePassiveOfferOp.encode(stream, encodedOperationBody.createPassiveOfferOp);
    break;
    case SET_OPTIONS:
    SetOptionsOp.encode(stream, encodedOperationBody.setOptionsOp);
    break;
    case CHANGE_TRUST:
    ChangeTrustOp.encode(stream, encodedOperationBody.changeTrustOp);
    break;
    case ALLOW_TRUST:
    AllowTrustOp.encode(stream, encodedOperationBody.allowTrustOp);
    break;
    case ACCOUNT_MERGE:
    AccountID.encode(stream, encodedOperationBody.destination);
    break;
    case INFLATION:
    break;
    case MANAGE_DATA:
    ManageDataOp.encode(stream, encodedOperationBody.manageDataOp);
    break;
    case BUMP_SEQUENCE:
    BumpSequenceOp.encode(stream, encodedOperationBody.bumpSequenceOp);
    break;
    }
    }

    public static void encodeForTestOnly(XdrDataOutputStream stream, OperationBody encodedOperationBody) throws IOException {
      stream.writeInt(encodedOperationBody.getDiscriminant().getValue());
      /*
      switch (encodedOperationBody.getDiscriminant()) {
        case CREATE_ACCOUNT:
          CreateAccountOp.encode(stream, encodedOperationBody.createAccountOp);
          break;
        case PAYMENT:
          PaymentOp.encode(stream, encodedOperationBody.paymentOp);
          break;
        case PATH_PAYMENT:
          PathPaymentOp.encode(stream, encodedOperationBody.pathPaymentOp);
          break;
        case MANAGE_OFFER:
          ManageOfferOp.encode(stream, encodedOperationBody.manageOfferOp);
          break;
        case CREATE_PASSIVE_OFFER:
          CreatePassiveOfferOp.encode(stream, encodedOperationBody.createPassiveOfferOp);
          break;
        case SET_OPTIONS:
          SetOptionsOp.encode(stream, encodedOperationBody.setOptionsOp);
          break;
        case CHANGE_TRUST:
          ChangeTrustOp.encode(stream, encodedOperationBody.changeTrustOp);
          break;
        case ALLOW_TRUST:
          AllowTrustOp.encode(stream, encodedOperationBody.allowTrustOp);
          break;
        case ACCOUNT_MERGE:
          AccountID.encode(stream, encodedOperationBody.destination);
          break;
        case INFLATION:
          break;
        case MANAGE_DATA:
          ManageDataOp.encode(stream, encodedOperationBody.manageDataOp);
          break;
        case BUMP_SEQUENCE:
          BumpSequenceOp.encode(stream, encodedOperationBody.bumpSequenceOp);
          break;
      }
      */
    }

    public static OperationBody decode(XdrDataInputStream stream) throws IOException {
    OperationBody decodedOperationBody = new OperationBody();
    OperationType discriminant = OperationType.decode(stream);
    decodedOperationBody.setDiscriminant(discriminant);
    switch (decodedOperationBody.getDiscriminant()) {
    case CREATE_ACCOUNT:
    decodedOperationBody.createAccountOp = CreateAccountOp.decode(stream);
    break;
    case PAYMENT:
    decodedOperationBody.paymentOp = PaymentOp.decode(stream);
    break;
    case PATH_PAYMENT:
    decodedOperationBody.pathPaymentOp = PathPaymentOp.decode(stream);
    break;
    case MANAGE_OFFER:
    decodedOperationBody.manageOfferOp = ManageOfferOp.decode(stream);
    break;
    case CREATE_PASSIVE_OFFER:
    decodedOperationBody.createPassiveOfferOp = CreatePassiveOfferOp.decode(stream);
    break;
    case SET_OPTIONS:
    decodedOperationBody.setOptionsOp = SetOptionsOp.decode(stream);
    break;
    case CHANGE_TRUST:
    decodedOperationBody.changeTrustOp = ChangeTrustOp.decode(stream);
    break;
    case ALLOW_TRUST:
    decodedOperationBody.allowTrustOp = AllowTrustOp.decode(stream);
    break;
    case ACCOUNT_MERGE:
    decodedOperationBody.destination = AccountID.decode(stream);
    break;
    case INFLATION:
    break;
    case MANAGE_DATA:
    decodedOperationBody.manageDataOp = ManageDataOp.decode(stream);
    break;
    case BUMP_SEQUENCE:
    decodedOperationBody.bumpSequenceOp = BumpSequenceOp.decode(stream);
    break;
    }
      return decodedOperationBody;
    }

  }
}
