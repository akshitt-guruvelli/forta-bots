from forta_agent import Finding, FindingType, FindingSeverity, transaction

nethermind_deployer="0x88dC3a2284FA62e0027d6D6B1fCfDd2141a143b8"
fort_bot_registry="0x61447385B019187daa48e91c55c02AF1F1f3F863"
forta_createAgent="0xA8A26969f7Be888D020B595340c490c02ec445dD"

'''implementation_abi={
  name: "implementation",
  type: "function",
  inputs: [],
  outputs: [{
    name: "impl",
    type: "address",
  ]},
}'''

createAgent_abi={"inputs":[{"internalType":"uint256",'name':'agentId','type':'uint256'},
                           {'internalType':'address','name':'owner','type':'address'},
                           {'internalType':'string','name':'metadata','type':'string'},
                           {'internalType':'uint256[]','name':'chainIds','type':'uint256[]'}],
                           'name':'createAgent','outputs':[],'stateMutability':'nonpayable','type':'function'}
def provide_handle_transaction(nether_deployer):
    def handle_transaction(transaction):

        findings=[]

        transaction_deployer=transaction.from_
        transaction_to=transaction.to
        if transaction_deployer==nether_deployer and transaction_to==fort_bot_registry:

            forta_event_log = transaction.filter_function(
            createAgent_abi, forta_createAgent)

            for object_ in forta_event_log:
                event_name = object_[1]

                if event_name!="createAgent":
                    continue


                findings.append(Finding({
                        'name': 'nethermind deployer detected',
                        'description': f'{nether_deployer} deployed a forta agent',
                        'alert_id': 'FORTA-7',
                        'type': FindingType.Info,
                        'severity': FindingSeverity.Info,
                        'metadata': {
                            'deployer': transaction.from_,
                            'deployed_to':transaction.to,
                            'event':event_name
                        }
                }))

        return findings

    return handle_transaction

real_handle_transaction = provide_handle_transaction(nethermind_deployer)

def handle_transaction(transaction):
    return real_handle_transaction(transaction)
