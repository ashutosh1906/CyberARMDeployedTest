def smtSelectSecurityControls(recommended_CDM,security_controls_bool_SMT):
    print "Size %s" % (len(security_controls_bool_SMT))
    for sec_index in range(len(security_controls_bool_SMT)):
        print "Index : %s Selection Flag : %s" % (sec_index,recommended_CDM[security_controls_bool_SMT[sec_index]])