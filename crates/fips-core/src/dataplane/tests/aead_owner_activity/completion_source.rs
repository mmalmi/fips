#[test]
fn completion_source_pump_reports_completion_activity_before_output_is_ready() {
    let owner = fmp_owner(84);
    let open_key = 84;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8));

    let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
    for (counter, payload) in packets {
        driver
            .mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(84, counter, 0, payload, open_key),
                )
                .unwrap(),
            )
            .unwrap();
    }

    let mut work = dispatch_available(&mut driver.mover, 8);
    assert_eq!(work.len(), 3);

    let mut completions = work
        .drain(..)
        .map(|work| complete_test_open_work(work, open_key))
        .collect::<VecDeque<_>>();
    let third = completions.pop_back().unwrap();
    let first = completions.pop_front().unwrap();
    let second = completions.pop_front().unwrap();

    let mut raw_ingress = VecDeque::new();
    let mut outbound = VecDeque::new();
    let mut sink = BatchRecordingOutputSink::default();
    let mut completion_source = VecDeque::from([third]);

    {
        let turn = pump_aead_output_completion_turn(
            &mut driver,
            AeadOutputCompletionTurn {
                completions: &mut completion_source,
                completion_limit: 8,
                raw_ingress: &mut raw_ingress,
                router: &mut NullIngressRouter,
                raw_ingress_limit: 0,
                outbound: &mut outbound,
                outbound_limit: 0,
                sink: &mut sink,
                crypto_limit: 8,
            },
        );
        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 0);
        assert!(turn.summary().has_activity());
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
    }
    assert!(completion_source.is_empty());
    assert!(sink.outputs.is_empty());
    assert_eq!(sink.batch_calls, 0);

    completion_source.extend([first, second]);
    {
        let turn = pump_aead_output_completion_turn(
            &mut driver,
            AeadOutputCompletionTurn {
                completions: &mut completion_source,
                completion_limit: 8,
                raw_ingress: &mut raw_ingress,
                router: &mut NullIngressRouter,
                raw_ingress_limit: 0,
                outbound: &mut outbound,
                outbound_limit: 0,
                sink: &mut sink,
                crypto_limit: 8,
            },
        );
        assert_eq!(turn.summary().completions(), 2);
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 3);
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
    }

    assert!(completion_source.is_empty());
    assert_eq!(sink.batch_calls, 1);
    assert_eq!(sink.outputs.len(), 3);
    assert_eq!(sink.outputs[0].counter(), 100);
    assert_eq!(sink.outputs[1].counter(), 101);
    assert_eq!(sink.outputs[2].counter(), 102);
    assert_eq!(
        &sink.outputs[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"first"
    );
    assert_eq!(
        &sink.outputs[1].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"second"
    );
    assert_eq!(
        &sink.outputs[2].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"third"
    );
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
}
