--
-- PostgreSQL database dump
--

\restrict FK4fwHr72XzHx3bRTrxdqJXip667VS9ZObLZakIDzsg4nbXavJqYbMki1ZrrvU1

-- Dumped from database version 17.10
-- Dumped by pg_dump version 17.10

-- Started on 2026-07-02 12:30:17

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 228 (class 1259 OID 32772)
-- Name: alerts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.alerts (
    id bigint NOT NULL,
    alert_id character varying(100) NOT NULL,
    alert_title character varying(255) NOT NULL,
    alert_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    priority character varying(10) NOT NULL,
    confidence integer DEFAULT 0,
    risk_score integer DEFAULT 0,
    status character varying(50) DEFAULT 'open'::character varying,
    occurrence_count integer DEFAULT 1,
    source character varying(255),
    source_ip character varying(100),
    host character varying(255),
    username character varying(255),
    event_fingerprint character varying(64),
    alert_fingerprint character varying(64) NOT NULL,
    rule_matches jsonb,
    correlation_matches jsonb,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp with time zone,
    resolved_at timestamp with time zone,
    closed_at timestamp with time zone
);


ALTER TABLE public.alerts OWNER TO postgres;

--
-- TOC entry 227 (class 1259 OID 32771)
-- Name: alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.alerts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.alerts_id_seq OWNER TO postgres;

--
-- TOC entry 5030 (class 0 OID 0)
-- Dependencies: 227
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- TOC entry 226 (class 1259 OID 25163)
-- Name: correlation_events; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.correlation_events (
    id bigint NOT NULL,
    correlation_id uuid NOT NULL,
    correlation_type character varying(100) NOT NULL,
    severity character varying(20) NOT NULL,
    confidence integer DEFAULT 0 NOT NULL,
    risk_score integer DEFAULT 0 NOT NULL,
    related_user character varying(255),
    related_source_ip character varying(100),
    related_host character varying(255),
    event_count integer DEFAULT 1 NOT NULL,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    correlation_reason text,
    correlation_status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    event_fingerprint character varying(64),
    correlation_metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.correlation_events OWNER TO postgres;

--
-- TOC entry 225 (class 1259 OID 25162)
-- Name: correlation_events_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.correlation_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.correlation_events_id_seq OWNER TO postgres;

--
-- TOC entry 5031 (class 0 OID 0)
-- Dependencies: 225
-- Name: correlation_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.correlation_events_id_seq OWNED BY public.correlation_events.id;


--
-- TOC entry 224 (class 1259 OID 25144)
-- Name: detection_rules; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.detection_rules (
    id bigint NOT NULL,
    rule_name character varying(255) NOT NULL,
    rule_code character varying(100) NOT NULL,
    rule_type character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    source_type character varying(100),
    event_type_pattern text,
    message_pattern text,
    threshold_count integer,
    threshold_minutes integer,
    risk_score integer DEFAULT 0,
    is_enabled boolean DEFAULT true,
    created_by character varying(100) DEFAULT 'system'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.detection_rules OWNER TO postgres;

--
-- TOC entry 223 (class 1259 OID 25143)
-- Name: detection_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.detection_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.detection_rules_id_seq OWNER TO postgres;

--
-- TOC entry 5032 (class 0 OID 0)
-- Dependencies: 223
-- Name: detection_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.detection_rules_id_seq OWNED BY public.detection_rules.id;


--
-- TOC entry 242 (class 1259 OID 33884)
-- Name: incidents; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.incidents (
    id integer NOT NULL,
    incident_id character varying(30) NOT NULL,
    alert_id integer,
    title text,
    severity character varying(20),
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    assigned_to character varying(100),
    assigned_role character varying(50),
    notes text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at timestamp with time zone,
    investigating_at timestamp with time zone,
    closed_at timestamp with time zone
);


ALTER TABLE public.incidents OWNER TO postgres;

--
-- TOC entry 241 (class 1259 OID 33883)
-- Name: incidents_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.incidents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.incidents_id_seq OWNER TO postgres;

--
-- TOC entry 5033 (class 0 OID 0)
-- Dependencies: 241
-- Name: incidents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.incidents_id_seq OWNED BY public.incidents.id;


--
-- TOC entry 220 (class 1259 OID 24584)
-- Name: invalid_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.invalid_logs (
    id bigint NOT NULL,
    source character varying(100),
    raw_payload jsonb NOT NULL,
    validation_status character varying(20) NOT NULL,
    validation_errors jsonb,
    validation_warnings jsonb,
    collector_name character varying(100),
    rejection_reason text,
    received_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    validation_stage character varying(50),
    quarantine_hash character varying(64),
    quarantined_count integer DEFAULT 1
);


ALTER TABLE public.invalid_logs OWNER TO postgres;

--
-- TOC entry 219 (class 1259 OID 24583)
-- Name: invalid_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.invalid_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.invalid_logs_id_seq OWNER TO postgres;

--
-- TOC entry 5034 (class 0 OID 0)
-- Dependencies: 219
-- Name: invalid_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.invalid_logs_id_seq OWNED BY public.invalid_logs.id;


--
-- TOC entry 218 (class 1259 OID 16390)
-- Name: logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.logs (
    id bigint NOT NULL,
    source character varying(255) NOT NULL,
    host character varying(255),
    event_type character varying(100) NOT NULL,
    message text NOT NULL,
    severity character varying(20) NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    source_ip character varying(50),
    user_name character varying(255),
    metadata jsonb,
    record_number bigint,
    is_suspicious boolean DEFAULT false NOT NULL,
    detection_severity character varying(20),
    detection_reason text,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.logs OWNER TO postgres;

--
-- TOC entry 217 (class 1259 OID 16389)
-- Name: logs_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.logs_id_seq OWNER TO postgres;

--
-- TOC entry 5035 (class 0 OID 0)
-- Dependencies: 217
-- Name: logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.logs_id_seq OWNED BY public.logs.id;


--
-- TOC entry 232 (class 1259 OID 33090)
-- Name: notification_escalations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notification_escalations (
    id bigint NOT NULL,
    escalation_id character varying(100) NOT NULL,
    notification_id character varying(100) NOT NULL,
    alert_id character varying(100) NOT NULL,
    escalation_level integer NOT NULL,
    escalation_target character varying(255),
    escalation_reason text,
    escalated_at timestamp with time zone NOT NULL,
    acknowledged boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.notification_escalations OWNER TO postgres;

--
-- TOC entry 231 (class 1259 OID 33089)
-- Name: notification_escalations_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notification_escalations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notification_escalations_id_seq OWNER TO postgres;

--
-- TOC entry 5036 (class 0 OID 0)
-- Dependencies: 231
-- Name: notification_escalations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notification_escalations_id_seq OWNED BY public.notification_escalations.id;


--
-- TOC entry 238 (class 1259 OID 33129)
-- Name: notification_history; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notification_history (
    id bigint NOT NULL,
    notification_id character varying(100),
    alert_id character varying(100),
    recipient_email character varying(255),
    recipient_role character varying(100),
    severity character varying(50),
    delivery_status character varying(50),
    escalation_level integer DEFAULT 0,
    sent_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.notification_history OWNER TO postgres;

--
-- TOC entry 237 (class 1259 OID 33128)
-- Name: notification_history_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notification_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notification_history_id_seq OWNER TO postgres;

--
-- TOC entry 5037 (class 0 OID 0)
-- Dependencies: 237
-- Name: notification_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notification_history_id_seq OWNED BY public.notification_history.id;


--
-- TOC entry 240 (class 1259 OID 33140)
-- Name: notification_metrics; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notification_metrics (
    id bigint NOT NULL,
    metric_date date NOT NULL,
    total_sent integer DEFAULT 0,
    total_failed integer DEFAULT 0,
    total_suppressed integer DEFAULT 0,
    total_escalated integer DEFAULT 0,
    total_retried integer DEFAULT 0,
    avg_delivery_time_seconds numeric(10,2) DEFAULT 0,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.notification_metrics OWNER TO postgres;

--
-- TOC entry 239 (class 1259 OID 33139)
-- Name: notification_metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notification_metrics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notification_metrics_id_seq OWNER TO postgres;

--
-- TOC entry 5038 (class 0 OID 0)
-- Dependencies: 239
-- Name: notification_metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notification_metrics_id_seq OWNED BY public.notification_metrics.id;


--
-- TOC entry 236 (class 1259 OID 33118)
-- Name: notification_policies; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notification_policies (
    id bigint NOT NULL,
    policy_name character varying(255) NOT NULL,
    severity character varying(50) NOT NULL,
    initial_role character varying(100) NOT NULL,
    escalation_role character varying(100),
    escalation_minutes integer,
    second_escalation_role character varying(100),
    second_escalation_minutes integer,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.notification_policies OWNER TO postgres;

--
-- TOC entry 235 (class 1259 OID 33117)
-- Name: notification_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notification_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notification_policies_id_seq OWNER TO postgres;

--
-- TOC entry 5039 (class 0 OID 0)
-- Dependencies: 235
-- Name: notification_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notification_policies_id_seq OWNED BY public.notification_policies.id;


--
-- TOC entry 234 (class 1259 OID 33106)
-- Name: notification_recipients; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notification_recipients (
    id bigint NOT NULL,
    recipient_name character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    role character varying(100) NOT NULL,
    team character varying(100),
    phone character varying(50),
    slack_channel character varying(255),
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.notification_recipients OWNER TO postgres;

--
-- TOC entry 233 (class 1259 OID 33105)
-- Name: notification_recipients_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notification_recipients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notification_recipients_id_seq OWNER TO postgres;

--
-- TOC entry 5040 (class 0 OID 0)
-- Dependencies: 233
-- Name: notification_recipients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notification_recipients_id_seq OWNED BY public.notification_recipients.id;


--
-- TOC entry 230 (class 1259 OID 33068)
-- Name: notifications; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notifications (
    id bigint NOT NULL,
    notification_id character varying(100) NOT NULL,
    alert_id character varying(100) NOT NULL,
    notification_fingerprint character varying(64) NOT NULL,
    severity character varying(20) NOT NULL,
    recipient_group character varying(100) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    occurrence_count integer DEFAULT 1,
    delivery_attempts integer DEFAULT 0,
    last_delivery_attempt timestamp with time zone,
    delivery_status character varying(50),
    acknowledged_by character varying(255),
    acknowledged_at timestamp with time zone,
    first_seen timestamp with time zone NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    escalation_level integer DEFAULT 0
);


ALTER TABLE public.notifications OWNER TO postgres;

--
-- TOC entry 229 (class 1259 OID 33067)
-- Name: notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notifications_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notifications_id_seq OWNER TO postgres;

--
-- TOC entry 5041 (class 0 OID 0)
-- Dependencies: 229
-- Name: notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notifications_id_seq OWNED BY public.notifications.id;


--
-- TOC entry 222 (class 1259 OID 24607)
-- Name: unknown_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.unknown_logs (
    id bigint NOT NULL,
    source character varying(255),
    raw_payload jsonb NOT NULL,
    detected_format character varying(100),
    parser_confidence integer,
    classification_reason text,
    received_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    collector_name character varying(255),
    unknown_hash character varying(64),
    occurrence_count integer DEFAULT 1,
    log_type character varying(100),
    detection_confidence integer,
    first_seen timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.unknown_logs OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 24606)
-- Name: unknown_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.unknown_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.unknown_logs_id_seq OWNER TO postgres;

--
-- TOC entry 5042 (class 0 OID 0)
-- Dependencies: 221
-- Name: unknown_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.unknown_logs_id_seq OWNED BY public.unknown_logs.id;


--
-- TOC entry 4724 (class 2604 OID 32775)
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- TOC entry 4717 (class 2604 OID 25166)
-- Name: correlation_events id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.correlation_events ALTER COLUMN id SET DEFAULT nextval('public.correlation_events_id_seq'::regclass);


--
-- TOC entry 4711 (class 2604 OID 25147)
-- Name: detection_rules id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.detection_rules ALTER COLUMN id SET DEFAULT nextval('public.detection_rules_id_seq'::regclass);


--
-- TOC entry 4761 (class 2604 OID 33887)
-- Name: incidents id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.incidents ALTER COLUMN id SET DEFAULT nextval('public.incidents_id_seq'::regclass);


--
-- TOC entry 4704 (class 2604 OID 24587)
-- Name: invalid_logs id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.invalid_logs ALTER COLUMN id SET DEFAULT nextval('public.invalid_logs_id_seq'::regclass);


--
-- TOC entry 4701 (class 2604 OID 16393)
-- Name: logs id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.logs ALTER COLUMN id SET DEFAULT nextval('public.logs_id_seq'::regclass);


--
-- TOC entry 4740 (class 2604 OID 33093)
-- Name: notification_escalations id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_escalations ALTER COLUMN id SET DEFAULT nextval('public.notification_escalations_id_seq'::regclass);


--
-- TOC entry 4750 (class 2604 OID 33132)
-- Name: notification_history id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_history ALTER COLUMN id SET DEFAULT nextval('public.notification_history_id_seq'::regclass);


--
-- TOC entry 4753 (class 2604 OID 33143)
-- Name: notification_metrics id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_metrics ALTER COLUMN id SET DEFAULT nextval('public.notification_metrics_id_seq'::regclass);


--
-- TOC entry 4747 (class 2604 OID 33121)
-- Name: notification_policies id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_policies ALTER COLUMN id SET DEFAULT nextval('public.notification_policies_id_seq'::regclass);


--
-- TOC entry 4743 (class 2604 OID 33109)
-- Name: notification_recipients id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_recipients ALTER COLUMN id SET DEFAULT nextval('public.notification_recipients_id_seq'::regclass);


--
-- TOC entry 4733 (class 2604 OID 33071)
-- Name: notifications id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications ALTER COLUMN id SET DEFAULT nextval('public.notifications_id_seq'::regclass);


--
-- TOC entry 4707 (class 2604 OID 24610)
-- Name: unknown_logs id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.unknown_logs ALTER COLUMN id SET DEFAULT nextval('public.unknown_logs_id_seq'::regclass);


--
-- TOC entry 5010 (class 0 OID 32772)
-- Dependencies: 228
-- Data for Name: alerts; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.alerts (id, alert_id, alert_title, alert_type, severity, priority, confidence, risk_score, status, occurrence_count, source, source_ip, host, username, event_fingerprint, alert_fingerprint, rule_matches, correlation_matches, first_seen, last_seen, created_at, updated_at, acknowledged_at, resolved_at, closed_at) FROM stdin;
\.


--
-- TOC entry 5008 (class 0 OID 25163)
-- Dependencies: 226
-- Data for Name: correlation_events; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.correlation_events (id, correlation_id, correlation_type, severity, confidence, risk_score, related_user, related_source_ip, related_host, event_count, first_seen, last_seen, correlation_reason, correlation_status, event_fingerprint, correlation_metadata, created_at, updated_at) FROM stdin;
1	b25c8cee-d224-47b3-b0f5-ab2b17f187d3	failed_login_burst	high	90	75	admin	10.0.0.1	\N	6	2026-06-09 15:56:39.838824+05:30	2026-06-09 15:58:13.933474+05:30	6 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 15:58:13.933474+05:30	2026-06-09 15:58:13.936487+05:30
2	fc3dd8b1-8d3a-4be0-a5ca-484d25b7464b	failed_login_burst	high	90	75	admin	10.0.0.1	\N	7	2026-06-09 15:56:39.838824+05:30	2026-06-09 15:58:33.101138+05:30	7 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 15:58:33.101176+05:30	2026-06-09 15:58:33.142128+05:30
3	aea365ff-afce-49f0-9e7f-7ed40128c0a8	failed_login_burst	high	90	75	admin	10.0.0.1	\N	6	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:22.670801+05:30	6 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:22.67086+05:30	2026-06-09 16:14:22.672745+05:30
4	aa135b75-f866-44d3-9c59-a7819ad95b14	failed_login_burst	high	90	75	admin	10.0.0.1	\N	7	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:23.040702+05:30	7 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:23.041237+05:30	2026-06-09 16:14:23.04219+05:30
5	f56238a1-a2bc-41af-a1d5-4b3a172efc89	failed_login_burst	high	90	75	admin	10.0.0.1	\N	8	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:23.322399+05:30	8 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:23.322781+05:30	2026-06-09 16:14:23.329101+05:30
6	590f31ce-912f-4ef7-9132-e9e0d9f2b0af	failed_login_burst	high	90	75	admin	10.0.0.1	\N	9	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:23.538955+05:30	9 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:23.539819+05:30	2026-06-09 16:14:23.541954+05:30
7	976850b7-39f7-4a17-b41c-e003f8033fc2	failed_login_burst	high	90	75	admin	10.0.0.1	\N	10	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:23.758618+05:30	10 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:23.758618+05:30	2026-06-09 16:14:23.760574+05:30
8	ea99fc2c-38ab-41a1-a4f2-76e9979e9d15	failed_login_burst	high	90	75	admin	10.0.0.1	\N	11	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:23.938234+05:30	11 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:23.938234+05:30	2026-06-09 16:14:23.939585+05:30
9	6798987d-154b-419d-80e1-721c9e48c45b	failed_login_burst	high	90	75	admin	10.0.0.1	\N	12	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:14:24.142912+05:30	12 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:14:24.143872+05:30	2026-06-09 16:14:24.148508+05:30
10	02ca5dbf-afab-4dcc-92b4-522095868920	failed_login_burst	high	90	75	admin	10.0.0.1	\N	13	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:16:57.208994+05:30	13 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:16:57.208994+05:30	2026-06-09 16:16:57.210866+05:30
11	e182d1e1-5077-43d2-8f8b-f4e6d9e61142	failed_login_burst	high	90	75	admin	10.0.0.1	\N	14	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:16:57.410584+05:30	14 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:16:57.410584+05:30	2026-06-09 16:16:57.439544+05:30
12	b87fd4b9-8695-4609-80fc-c853e9aadaf8	failed_login_burst	high	90	75	admin	10.0.0.1	\N	15	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:16:57.94909+05:30	15 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:16:57.94909+05:30	2026-06-09 16:16:57.950895+05:30
13	cb9f3c8b-0671-4759-b654-caf4e6eed258	failed_login_burst	high	90	75	admin	10.0.0.1	\N	16	2026-06-09 16:13:44.440032+05:30	2026-06-09 16:16:58.708068+05:30	16 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:16:58.708068+05:30	2026-06-09 16:16:58.740804+05:30
14	af90cd79-6581-4005-8f9d-e32244917573	failed_login_burst	high	90	75	admin	10.0.0.1	\N	6	2026-06-09 16:31:09.529889+05:30	2026-06-09 16:31:13.844256+05:30	6 failed login attempts from 10.0.0.1 for user 'admin' within 5 minutes	active	b6d634e45c6e7d071b0a914063882abe82d3b47e7f86143753c7d0555ada18af	\N	2026-06-09 16:31:13.844615+05:30	2026-06-09 16:31:13.847524+05:30
\.


--
-- TOC entry 5006 (class 0 OID 25144)
-- Dependencies: 224
-- Data for Name: detection_rules; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.detection_rules (id, rule_name, rule_code, rule_type, severity, source_type, event_type_pattern, message_pattern, threshold_count, threshold_minutes, risk_score, is_enabled, created_by, created_at, updated_at) FROM stdin;
1	PowerShell Detection	POWERSHELL_EXEC	pattern	high	\N	\N	powershell	\N	\N	80	t	system	2026-06-08 15:47:32.188724+05:30	2026-06-08 15:47:32.188724+05:30
\.


--
-- TOC entry 5024 (class 0 OID 33884)
-- Dependencies: 242
-- Data for Name: incidents; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.incidents (id, incident_id, alert_id, title, severity, status, assigned_to, assigned_role, notes, created_at, updated_at, acknowledged_at, investigating_at, closed_at) FROM stdin;
\.


--
-- TOC entry 5002 (class 0 OID 24584)
-- Dependencies: 220
-- Data for Name: invalid_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.invalid_logs (id, source, raw_payload, validation_status, validation_errors, validation_warnings, collector_name, rejection_reason, received_at, validation_stage, quarantine_hash, quarantined_count) FROM stdin;
\.


--
-- TOC entry 5000 (class 0 OID 16390)
-- Dependencies: 218
-- Data for Name: logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.logs (id, source, host, event_type, message, severity, "timestamp", source_ip, user_name, metadata, record_number, is_suspicious, detection_severity, detection_reason, ingested_at) FROM stdin;
3	windows-event-viewer	DESKTOP-SU06TL9	windows_event_1073872930	Audit trail: LENGTH: '789' ACTION :[528] 'SELECT * FROM (SELECT sql_id, force_matching_signature, sql_text, parsing_schema_name,         module, action, elapsed_time, cpu_time, buffer_gets, bind_data,         disk_reads, direct_writes, rows_processed, fetches, executions,         end_of_fetch_count, optimizer_cost, first_load_time, optimizer_env,         priority, command_type, stat_period, active_stat_period, plan_hash_value        , sql_seq, con_dbid, last_exec_start_time       FROM sys.user_sqlset_statements) WHERE (last_exec_start_time < '2025-06-18/18:08:53')' DATABASE USER:[3] 'SYS' PRIVILEGE :[6] 'SYSDBA' CLIENT USER:[0] '' CLIENT TERMINAL:[15] 'DESKTOP-SU06TL9' STATUS:[1] '0' DBID:[9] '351708872' SESSIONID:[6] '390046' USERHOST:[15] 'DESKTOP-SU06TL9' CLIENT ADDRESS:[0] '' ACTION NUMBER:[1] '3' .	low	2026-06-26 18:08:53+05:30	\N	\N	{"event_id": "1073872930", "log_type": "Application", "provider": "Oracle.xe", "record_number": 139141, "detected_format": "text", "event_fingerprint": "d18194d463a3c5a0cf56413494d16358fc25c22f2fc9d17868ca032a7bc75bfe", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	139141	f	low	\N	2026-06-26 18:08:57.274476+05:30
4	windows-event-viewer	DESKTOP-SU06TL9	windows_event_1073872930	Audit trail: LENGTH: '2250' ACTION :[1988] 'SELECT * FROM (SELECT sql_id, force_matching_signature,           NVL(plan_hash_value, 0) plan_hash_value,           sql_fulltext as sql_text, parsing_schema_name,           module, action, elapsed_time, cpu_time, buffer_gets,            last_active_child_address,           TO_CHAR(first_load_time, 'YYYY-MM-DD/HH24:MI:SS') first_load_time,           last_load_time,          disk_reads, direct_writes, rows_processed, fetches, executions,            end_of_fetch_count, optimizer_cost, optimizer_env,           command_type, loaded_versions, bind_data, last_active_time, con_dbid,          TO_CHAR(last_exec_start_time, 'YYYY-MM-DD/HH24:MI:SS')           last_exec_start_time         FROM sys.v_$sqlarea_plan_hash s) WHERE ( (module is null or (module != 'SYS_AI_MODULE' and module != 'SYS_AUTO_STS_MODULE')) and sql_text not like 'SELECT /* DS_SVC */%'                  and sql_text not like 'SELECT /* OPT_DYN_SAMP */%'                  and sql_text not like '/*AUTO_INDEX:ddl*/%'                  and sql_text not like '%/*+�ms_stats%'                  and sql_text not like '%/* SQL Analyze(%'                  and command_type not in (9, 10, 11)                  and plan_hash_value > 0                   and (con_dbid, force_matching_signature) not in                      (select /*+ unnest no_merge */                        sss.con_dbid, sss.force_matching_signature                       from wri$_sqlset_definitions ssf,                             wri$_sqlset_statements sss                        where ssf.id = sss.sqlset_id                          and ssf.con_dbid = sss.con_dbid                         and ssf.owner = 'SYS' and ssf.name = 'SYS_AUTO_STS' and ssf.con_dbid =                                   sys_context('userenv','con_dbid')                         and force_matching_signature > 0                       group by sss.con_dbid, sss.sqlset_id,                                 sss.force_matching_signature                       having count(*) > 1000) )' DATABASE USER:[3] 'SYS' PRIVILEGE :[6] 'SYSDBA' CLIENT USER:[0] '' CLIENT TERMINAL:[15] 'DESKTOP-SU06TL9' STATUS:[1] '0' DBID:[9] '351708872' SESSIONID:[6] '390046' USERHOST:[15] 'DESKTOP-SU06TL9' CLIENT ADDRESS:[0] '' ACTION NUMBER:[1] '3' .	low	2026-06-26 18:08:54+05:30	\N	\N	{"event_id": "1073872930", "log_type": "Application", "provider": "Oracle.xe", "record_number": 139142, "decoding_chain": ["url"], "detected_format": "text", "decoding_applied": true, "event_fingerprint": "cc9552130fa66b4afd0068067291220e094d540461b782af4ef8cc7b36e0f1ab", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "parsing_confidence": 0.3, "validation_warnings": ["Non-standard severity value"]}	139142	f	low	\N	2026-06-26 18:08:57.317343+05:30
5	windows-event-viewer	DESKTOP-SU06TL9	windows_event_2	Secure Trustlet Id 0 and Pid 0 stopped with status 0.	low	2026-06-26 18:13:53+05:30	\N	\N	{"event_id": "2", "log_type": "System", "provider": "Microsoft-Windows-IsolatedUserMode", "record_number": 80707, "detected_format": "text", "event_fingerprint": "7c85b0985c628cb703c1b777254def93114e2b6845532e3ddb821edf9fff6cbd", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	80707	f	low	\N	2026-06-26 18:13:57.733908+05:30
6	windows-event-viewer	DESKTOP-SU06TL9	windows_event_5	Secure Trustlet NULL Id 0 and Pid 0 started with status 0.	low	2026-06-26 18:13:53+05:30	\N	\N	{"event_id": "5", "log_type": "System", "provider": "Microsoft-Windows-IsolatedUserMode", "record_number": 80708, "detected_format": "text", "event_fingerprint": "39a6f4289765a41a09ad6b47a5e5868c920984fd815c1572e8d6c05829e6155f", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	80708	f	low	\N	2026-06-26 18:13:57.758905+05:30
7	windows-event-viewer	DESKTOP-SU06TL9	windows_event_-2147417855	[	low	2026-06-26 18:13:55+05:30	\N	\N	{"event_id": "-2147417855", "log_type": "Application", "provider": "Edge", "record_number": 139143, "detected_format": "text", "event_fingerprint": "0a684ab6b4ad10141f7fb468f69bd60725d1c605e81e265b43c81b6f04dc8d7e", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	139143	f	low	\N	2026-06-26 18:13:57.786983+05:30
1	chrome-browser	DESKTOP-SU06TL9	browser.url_visit	Visited URL: https://app.hrone.cloud/app/myprofile/calendar	low	2026-06-26 17:51:53.287468+05:30	\N	\N	{"title": "HROne", "browser": "chrome", "profile": "Default", "visit_id": 97791, "typed_count": 1, "visit_count": 51, "record_number": 100097791, "detected_format": "text", "transition_name": "Auto_Bookmark", "transition_type": 805306370, "event_fingerprint": "358d55bb2027555eebaf93999afd838c775b8b1b3e39f34c853fe6cd031a388a", "log_classification": {"log_type": "chrome_browser", "confidence": 95, "log_subtype": "url_visit", "classification_reason": "Source or event type matches Chrome browser log collector"}, "validation_warnings": ["Non-standard severity value"]}	100097791	f	low	\N	2026-06-26 17:52:04.227806+05:30
2	chrome-browser	DESKTOP-SU06TL9	browser.url_visit	Visited URL: https://app.hrone.cloud/app/myprofile/calendar	low	2026-06-26 17:53:19.800959+05:30	\N	\N	{"title": "HROne", "browser": "chrome", "profile": "Default", "visit_id": 97792, "typed_count": 1, "visit_count": 52, "record_number": 100097792, "detected_format": "text", "transition_name": "Auto_Bookmark", "transition_type": 805306370, "event_fingerprint": "923f19d0bb6566ac041a83bf6c8523c5ae8cc5f83ad1f4ff45c5e2bfc6708d40", "log_classification": {"log_type": "chrome_browser", "confidence": 95, "log_subtype": "url_visit", "classification_reason": "Source or event type matches Chrome browser log collector"}, "validation_warnings": ["Non-standard severity value"]}	100097792	f	low	\N	2026-06-26 17:53:30.146597+05:30
8	windows-event-viewer	DESKTOP-SU06TL9	windows_event_10016	<The description for Event ID ( 10016 ) in Source ( 'DCOM' ) could not be found. It contains the following insertion string(s):'application-specific, Local, Activation, {2593F8B9-4EAF-457C-B68A-50F6B8EA6B54}, {15C20B67-12E7-4BB6-92BB-7AFF07997402}, DESKTOP-SU06TL9, HP, S-1-5-21-1564224993-2878564883-2443171753-1001, LocalHost (Using LRPC), Unavailable, Unavailable'.>	low	2026-06-26 18:14:24+05:30	\N	\N	{"event_id": "10016", "log_type": "System", "provider": "DCOM", "record_number": 80709, "detected_format": "text", "event_fingerprint": "092bdd37a94df8f223a891a4f1530a1218566292db4127be3a1dec1eb781fd3b", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	80709	f	low	\N	2026-06-26 18:14:27.974881+05:30
9	windows-event-viewer	DESKTOP-SU06TL9	windows_event_-2147483392	[	low	2026-06-26 18:14:24+05:30	\N	\N	{"event_id": "-2147483392", "log_type": "Application", "provider": "Edge", "record_number": 139144, "detected_format": "text", "event_fingerprint": "0178cc7e1a1175029f4285dcd5becfa29376be39c0dfe022a6a7da83da2f3dc2", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	139144	f	low	\N	2026-06-26 18:14:28.005244+05:30
10	windows-event-viewer	DESKTOP-SU06TL9	windows_event_-2147483392	[	low	2026-06-26 18:14:43+05:30	\N	\N	{"event_id": "-2147483392", "log_type": "Application", "provider": "Chrome", "record_number": 139145, "detected_format": "text", "event_fingerprint": "6bd6f4cef404282821a413d408d6fd873e1dcc8c4cd3a964cca9861193f9a174", "log_classification": {"log_type": "windows_event", "confidence": 95, "log_subtype": "system", "classification_reason": "Detected EventID and Provider fields"}, "validation_warnings": ["Non-standard severity value"]}	139145	f	low	\N	2026-06-26 18:14:48.084109+05:30
\.


--
-- TOC entry 5014 (class 0 OID 33090)
-- Dependencies: 232
-- Data for Name: notification_escalations; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.notification_escalations (id, escalation_id, notification_id, alert_id, escalation_level, escalation_target, escalation_reason, escalated_at, acknowledged, created_at) FROM stdin;
69	ESC-B8ADD6FE	NTF-291353CC	ALT-20260619-0004	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-19 16:11:22.450741+05:30	f	2026-06-19 16:11:22.450741+05:30
70	ESC-46F5E74B	NTF-B64B0DD5	ALT-20260619-0005	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-19 16:11:25.972355+05:30	f	2026-06-19 16:11:25.972355+05:30
71	ESC-48D405D3	NTF-291353CC	ALT-20260619-0004	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 20 minutes	2026-06-19 16:20:22.418404+05:30	f	2026-06-19 16:20:22.418404+05:30
72	ESC-493A8584	NTF-B64B0DD5	ALT-20260619-0005	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 20 minutes	2026-06-19 16:20:26.223027+05:30	f	2026-06-19 16:20:26.223027+05:30
73	ESC-8E146107	NTF-22B429B0	ALT-20260622-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-22 11:22:45.974566+05:30	f	2026-06-22 11:22:45.974566+05:30
74	ESC-7BDD5328	NTF-22B429B0	ALT-20260622-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 10 minutes	2026-06-22 11:27:45.958436+05:30	f	2026-06-22 11:27:45.958436+05:30
75	ESC-A8EF5969	NTF-7EE07D8D	ALT-20260622-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-22 11:42:45.950833+05:30	f	2026-06-22 11:42:45.950833+05:30
76	ESC-7F4683E1	NTF-7EE07D8D	ALT-20260622-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 10 minutes	2026-06-22 11:47:45.957893+05:30	f	2026-06-22 11:47:45.957893+05:30
77	ESC-5D44FDF1	NTF-58C8C9BD	ALT-20260624-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-24 12:10:27.559864+05:30	f	2026-06-24 12:10:27.559864+05:30
78	ESC-4257D462	NTF-58C8C9BD	ALT-20260624-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 20 minutes	2026-06-24 12:25:27.524736+05:30	f	2026-06-24 12:25:27.524736+05:30
14	ESC-B308EE86	NTF-6E063994	ALT-20260612-0001	1	test_responder_l1	Level-1 escalation: unacknowledged for 1 minutes	2026-06-12 15:00:23.706177+05:30	f	2026-06-12 15:00:23.706177+05:30
15	ESC-B9692CC0	NTF-6E063994	ALT-20260612-0001	2	test_responder_l2	Level-2 escalation: unacknowledged for 2 minutes	2026-06-12 15:00:26.631232+05:30	f	2026-06-12 15:00:26.631232+05:30
39	ESC-C89CB769	NTF-10755AFA	ALT-20260612-0001	1	SOC_MANAGER	Level-1 escalation: unacknowledged for 5 minutes	2026-06-12 16:06:18.565876+05:30	f	2026-06-12 16:06:18.565876+05:30
40	ESC-B94EB912	NTF-10755AFA	ALT-20260612-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 10 minutes	2026-06-12 16:11:18.546853+05:30	f	2026-06-12 16:11:18.546853+05:30
41	ESC-E4A523ED	NTF-C3037248	ALT-20260617-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-17 16:50:16.502654+05:30	f	2026-06-17 16:50:16.502654+05:30
42	ESC-39640871	NTF-C3037248	ALT-20260617-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 20 minutes	2026-06-17 17:05:16.47974+05:30	f	2026-06-17 17:05:16.47974+05:30
43	ESC-218D6A56	NTF-C145FE15	ALT-20260617-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-17 17:59:21.614598+05:30	f	2026-06-17 17:59:21.614598+05:30
44	ESC-B467F355	NTF-C145FE15	ALT-20260617-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 10 minutes	2026-06-17 18:04:21.591064+05:30	f	2026-06-17 18:04:21.591064+05:30
45	ESC-E1F02208	NTF-D11B3FBB	ALT-20260618-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-18 11:45:41.398026+05:30	f	2026-06-18 11:45:41.398026+05:30
46	ESC-3B7307A2	NTF-D11B3FBB	ALT-20260618-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 20 minutes	2026-06-18 12:00:41.386528+05:30	f	2026-06-18 12:00:41.386528+05:30
55	ESC-B8077FBB	NTF-51333C99	ALT-20260618-0001	1	L2_SOC	Level-1 escalation: unacknowledged for 5 minutes	2026-06-18 14:31:50.154172+05:30	f	2026-06-18 14:31:50.154172+05:30
56	ESC-1B64E782	NTF-51333C99	ALT-20260618-0001	2	SOC_MANAGER	Level-2 escalation: unacknowledged for 20 minutes	2026-06-18 14:46:50.144439+05:30	f	2026-06-18 14:46:50.144439+05:30
\.


--
-- TOC entry 5020 (class 0 OID 33129)
-- Dependencies: 238
-- Data for Name: notification_history; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.notification_history (id, notification_id, alert_id, recipient_email, recipient_role, severity, delivery_status, escalation_level, sent_at, acknowledged_at, created_at) FROM stdin;
664	NTF-821959D2	ALT-20260619-0004	\N	\N	high	suppressed	0	\N	\N	2026-06-19 12:10:11.37098+05:30
533	NTF-FBE3F2CB	ALT-20260617-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	high	delivered	0	\N	\N	2026-06-17 17:49:00.307149+05:30
534	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:50:55.74534+05:30
535	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:50:56.564608+05:30
536	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:50:57.170557+05:30
537	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:50:57.811492+05:30
538	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:50:58.502166+05:30
539	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:53:56.389323+05:30
540	NTF-FBE3F2CB	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 17:53:56.745357+05:30
541	NTF-C145FE15	ALT-20260617-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	critical	delivered	0	\N	\N	2026-06-17 17:54:00.338625+05:30
542	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:01.113437+05:30
543	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:01.675676+05:30
544	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:02.251598+05:30
545	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:02.767829+05:30
546	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:03.225429+05:30
547	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:03.76188+05:30
548	NTF-C145FE15	ALT-20260617-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-17 17:54:04.233194+05:30
549	NTF-C145FE15	ALT-20260617-0001	indrajeetthorat1648@gmail.com	L2_SOC	critical	delivered	1	\N	\N	2026-06-17 17:59:24.604211+05:30
550	NTF-C145FE15	ALT-20260617-0001	thoratindrajeet30@gmail.com	SOC_MANAGER	critical	delivered	2	\N	\N	2026-06-17 18:04:24.506427+05:30
556	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:44:28.143284+05:30
557	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:44:30.540057+05:30
558	NTF-D11B3FBB	ALT-20260618-0001	indrajeetthorat1648@gmail.com	L2_SOC	high	delivered	1	\N	\N	2026-06-18 11:45:44.455661+05:30
559	NTF-D11B3FBB	ALT-20260618-0001	thoratindrajeet30@gmail.com	SOC_MANAGER	high	delivered	2	\N	\N	2026-06-18 12:00:44.639931+05:30
629	NTF-5F20AAAF	ALT-20260619-0004	\N	\N	high	suppressed	0	\N	\N	2026-06-19 12:02:45.406452+05:30
698	NTF-D0FBAEFA	ALT-20260619-0005	\N	\N	high	suppressed	0	\N	\N	2026-06-19 12:10:15.279178+05:30
733	NTF-B64B0DD5	ALT-20260619-0005	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	high	delivered	0	\N	\N	2026-06-19 15:54:03.017862+05:30
734	NTF-291353CC	ALT-20260619-0004	shubhamfutane53@gmail.com	L2_SOC	high	delivered	1	\N	\N	2026-06-19 16:11:25.922835+05:30
735	NTF-B64B0DD5	ALT-20260619-0005	shubhamfutane53@gmail.com	L2_SOC	high	delivered	1	\N	\N	2026-06-19 16:11:29.066432+05:30
736	NTF-291353CC	ALT-20260619-0004	patwardhannikhil900@gmail.com	SOC_MANAGER	high	delivered	2	\N	\N	2026-06-19 16:20:26.190295+05:30
737	NTF-B64B0DD5	ALT-20260619-0005	patwardhannikhil900@gmail.com	SOC_MANAGER	high	delivered	2	\N	\N	2026-06-19 16:20:29.639493+05:30
663	NTF-D299267C	ALT-20260619-0005	\N	\N	high	suppressed	0	\N	\N	2026-06-19 12:02:50.268405+05:30
738	NTF-22B429B0	ALT-20260622-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	critical	delivered	0	\N	\N	2026-06-22 11:17:39.111992+05:30
739	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:53.381255+05:30
740	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:54.227609+05:30
741	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:55.107793+05:30
742	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:56.157929+05:30
743	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:57.239082+05:30
744	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:58.174254+05:30
745	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:17:59.184347+05:30
746	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:18:00.125385+05:30
747	NTF-22B429B0	ALT-20260622-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-22 11:18:01.088837+05:30
748	NTF-22B429B0	ALT-20260622-0001	shubhamfutane53@gmail.com	L2_SOC	critical	delivered	1	\N	\N	2026-06-22 11:22:49.153513+05:30
749	NTF-22B429B0	ALT-20260622-0001	patwardhannikhil900@gmail.com	SOC_MANAGER	critical	delivered	2	\N	\N	2026-06-22 11:27:49.220638+05:30
750	NTF-7EE07D8D	ALT-20260622-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	critical	delivered	0	\N	\N	2026-06-22 11:37:30.202118+05:30
751	NTF-7EE07D8D	ALT-20260622-0001	shubhamfutane53@gmail.com	L2_SOC	critical	delivered	1	\N	\N	2026-06-22 11:42:48.918823+05:30
752	NTF-7EE07D8D	ALT-20260622-0001	patwardhannikhil900@gmail.com	SOC_MANAGER	critical	delivered	2	\N	\N	2026-06-22 11:47:49.064642+05:30
753	NTF-58C8C9BD	ALT-20260624-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-24 12:04:34.07734+05:30
754	NTF-58C8C9BD	ALT-20260624-0001	shubhamfutane53@gmail.com	L2_SOC	high	delivered	1	\N	\N	2026-06-24 12:10:31.365167+05:30
755	NTF-58C8C9BD	ALT-20260624-0001	patwardhannikhil900@gmail.com	SOC_MANAGER	high	delivered	2	\N	\N	2026-06-24 12:25:30.477379+05:30
503	NTF-10755AFA	ALT-20260612-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	critical	delivered	0	\N	\N	2026-06-12 16:00:50.719875+05:30
504	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:00:52.299278+05:30
505	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:30.96378+05:30
248	NTF-6E063994	ALT-20260612-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	critical	delivered	0	\N	\N	2026-06-12 14:23:54.83726+05:30
249	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:40.55301+05:30
250	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:41.42578+05:30
251	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:45.979381+05:30
252	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:46.195394+05:30
253	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:46.454985+05:30
254	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:47.554668+05:30
255	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:24:48.617736+05:30
256	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:25:00.361603+05:30
257	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:25:00.971569+05:30
258	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:15.458401+05:30
259	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:16.105135+05:30
260	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:16.826356+05:30
261	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:17.510091+05:30
262	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:18.24965+05:30
263	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:18.963602+05:30
264	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:19.637439+05:30
265	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:20.288941+05:30
266	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:20.989868+05:30
267	NTF-6E063994	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 14:27:21.673874+05:30
506	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:31.656809+05:30
507	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:32.954702+05:30
270	NTF-6E063994	ALT-20260612-0001	l1@example.com	test_responder_l1	critical	delivered	1	\N	\N	2026-06-12 15:00:26.602297+05:30
271	NTF-6E063994	ALT-20260612-0001	l2@example.com	test_responder_l2	critical	delivered	2	\N	\N	2026-06-12 15:00:29.462977+05:30
508	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:33.510967+05:30
509	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:34.290148+05:30
510	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:34.769341+05:30
511	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:35.277136+05:30
512	NTF-10755AFA	ALT-20260612-0001	\N	\N	critical	suppressed	0	\N	\N	2026-06-12 16:01:35.754482+05:30
513	NTF-10755AFA	ALT-20260612-0001	thoratindrajeet30@gmail.com	SOC_MANAGER	critical	delivered	1	\N	\N	2026-06-12 16:06:21.492029+05:30
514	NTF-10755AFA	ALT-20260612-0001	thoratindrajeet30@gmail.com	SOC_MANAGER	critical	delivered	2	\N	\N	2026-06-12 16:11:21.365059+05:30
515	NTF-C3037248	ALT-20260617-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	high	delivered	0	\N	\N	2026-06-17 16:45:04.862188+05:30
516	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:04.909173+05:30
517	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:05.50685+05:30
518	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:06.070649+05:30
519	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:06.669797+05:30
520	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:07.241653+05:30
521	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:07.852136+05:30
522	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:08.641144+05:30
523	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:09.325692+05:30
524	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:09.96793+05:30
525	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:10.643156+05:30
526	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:11.324173+05:30
527	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:12.022514+05:30
528	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:12.668203+05:30
529	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:13.435301+05:30
530	NTF-C3037248	ALT-20260617-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-17 16:49:14.069036+05:30
531	NTF-C3037248	ALT-20260617-0001	indrajeetthorat1648@gmail.com	L2_SOC	high	delivered	1	\N	\N	2026-06-17 16:50:19.766964+05:30
532	NTF-C3037248	ALT-20260617-0001	thoratindrajeet30@gmail.com	SOC_MANAGER	high	delivered	2	\N	\N	2026-06-17 17:05:19.336206+05:30
551	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:40:11.692063+05:30
552	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:40:17.204052+05:30
553	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:43:59.693762+05:30
554	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:44:00.101465+05:30
555	NTF-D11B3FBB	ALT-20260618-0001	\N	\N	high	suppressed	0	\N	\N	2026-06-18 11:44:00.653377+05:30
626	NTF-51333C99	ALT-20260618-0001	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	high	delivered	0	\N	\N	2026-06-18 14:26:20.236282+05:30
627	NTF-51333C99	ALT-20260618-0001	shubhamfutane53@gmail.com	L2_SOC	high	delivered	1	\N	\N	2026-06-18 14:31:53.314187+05:30
628	NTF-51333C99	ALT-20260618-0001	patwardhannikhil900@gmail.com	SOC_MANAGER	high	delivered	2	\N	\N	2026-06-18 14:46:53.296455+05:30
699	NTF-291353CC	ALT-20260619-0004	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	high	delivered	0	\N	\N	2026-06-19 15:53:55.498627+05:30
\.


--
-- TOC entry 5022 (class 0 OID 33140)
-- Dependencies: 240
-- Data for Name: notification_metrics; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.notification_metrics (id, metric_date, total_sent, total_failed, total_suppressed, total_escalated, total_retried, avg_delivery_time_seconds, created_at) FROM stdin;
2	2026-06-17	8	0	29	4	0	359.42	2026-06-17 16:45:04.885311+05:30
3	2026-06-18	41	4	15	12	0	449439.37	2026-06-18 11:40:11.715065+05:30
1	2026-06-12	192	21	102	40	0	-15203.57	2026-06-12 09:25:23.745629+05:30
4	2026-06-19	60	6	16	16	0	529092.82	2026-06-19 12:02:45.424726+05:30
5	2026-06-22	7	0	9	4	0	313.10	2026-06-22 11:17:39.183758+05:30
6	2026-06-24	2	0	1	2	0	1256.45	2026-06-24 12:04:34.104339+05:30
\.


--
-- TOC entry 5018 (class 0 OID 33118)
-- Dependencies: 236
-- Data for Name: notification_policies; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.notification_policies (id, policy_name, severity, initial_role, escalation_role, escalation_minutes, second_escalation_role, second_escalation_minutes, is_active, created_at) FROM stdin;
2	Critical Alert Policy	critical	INCIDENT_TEAM	L2_SOC	5	SOC_MANAGER	10	t	2026-06-11 15:20:04.611688+05:30
1	High Alert Policy	high	INCIDENT_TEAM	L2_SOC	5	SOC_MANAGER	20	t	2026-06-11 15:20:04.611688+05:30
\.


--
-- TOC entry 5016 (class 0 OID 33106)
-- Dependencies: 234
-- Data for Name: notification_recipients; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.notification_recipients (id, recipient_name, email, role, team, phone, slack_channel, is_active, created_at, updated_at) FROM stdin;
1	SOC Analyst L1	shubhamfutane53@gmail.com	L1_SOC	SOC	\N	\N	t	2026-06-11 15:17:13.993329+05:30	2026-06-11 15:17:13.993329+05:30
3	SOC Manager	patwardhannikhil900@gmail.com	SOC_MANAGER	SOC	\N	\N	t	2026-06-11 15:17:13.993329+05:30	2026-06-11 15:17:13.993329+05:30
4	Incident Response Team	indrajeetthorat1648@gmail.com	INCIDENT_TEAM	IR	\N	\N	t	2026-06-11 15:17:13.993329+05:30	2026-06-11 15:17:13.993329+05:30
2	SOC Analyst L2	shubhamfutane53@gmail.com	L2_SOC	SOC	\N	\N	t	2026-06-11 15:17:13.993329+05:30	2026-06-11 15:17:13.993329+05:30
\.


--
-- TOC entry 5012 (class 0 OID 33068)
-- Dependencies: 230
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.notifications (id, notification_id, alert_id, notification_fingerprint, severity, recipient_group, status, occurrence_count, delivery_attempts, last_delivery_attempt, delivery_status, acknowledged_by, acknowledged_at, first_seen, last_seen, created_at, updated_at, escalation_level) FROM stdin;
\.


--
-- TOC entry 5004 (class 0 OID 24607)
-- Dependencies: 222
-- Data for Name: unknown_logs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.unknown_logs (id, source, raw_payload, detected_format, parser_confidence, classification_reason, received_at, collector_name, unknown_hash, occurrence_count, log_type, detection_confidence, first_seen) FROM stdin;
\.


--
-- TOC entry 5043 (class 0 OID 0)
-- Dependencies: 227
-- Name: alerts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.alerts_id_seq', 1, false);


--
-- TOC entry 5044 (class 0 OID 0)
-- Dependencies: 225
-- Name: correlation_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.correlation_events_id_seq', 14, true);


--
-- TOC entry 5045 (class 0 OID 0)
-- Dependencies: 223
-- Name: detection_rules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.detection_rules_id_seq', 1, true);


--
-- TOC entry 5046 (class 0 OID 0)
-- Dependencies: 241
-- Name: incidents_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.incidents_id_seq', 84, true);


--
-- TOC entry 5047 (class 0 OID 0)
-- Dependencies: 219
-- Name: invalid_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.invalid_logs_id_seq', 1, false);


--
-- TOC entry 5048 (class 0 OID 0)
-- Dependencies: 217
-- Name: logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.logs_id_seq', 10, true);


--
-- TOC entry 5049 (class 0 OID 0)
-- Dependencies: 231
-- Name: notification_escalations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.notification_escalations_id_seq', 78, true);


--
-- TOC entry 5050 (class 0 OID 0)
-- Dependencies: 237
-- Name: notification_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.notification_history_id_seq', 755, true);


--
-- TOC entry 5051 (class 0 OID 0)
-- Dependencies: 239
-- Name: notification_metrics_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.notification_metrics_id_seq', 6, true);


--
-- TOC entry 5052 (class 0 OID 0)
-- Dependencies: 235
-- Name: notification_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.notification_policies_id_seq', 463, true);


--
-- TOC entry 5053 (class 0 OID 0)
-- Dependencies: 233
-- Name: notification_recipients_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.notification_recipients_id_seq', 763, true);


--
-- TOC entry 5054 (class 0 OID 0)
-- Dependencies: 229
-- Name: notifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.notifications_id_seq', 1, false);


--
-- TOC entry 5055 (class 0 OID 0)
-- Dependencies: 221
-- Name: unknown_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.unknown_logs_id_seq', 1, false);


--
-- TOC entry 4807 (class 2606 OID 32791)
-- Name: alerts alerts_alert_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_alert_fingerprint_key UNIQUE (alert_fingerprint);


--
-- TOC entry 4809 (class 2606 OID 32789)
-- Name: alerts alerts_alert_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_alert_id_key UNIQUE (alert_id);


--
-- TOC entry 4811 (class 2606 OID 32787)
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- TOC entry 4792 (class 2606 OID 25178)
-- Name: correlation_events correlation_events_correlation_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.correlation_events
    ADD CONSTRAINT correlation_events_correlation_id_key UNIQUE (correlation_id);


--
-- TOC entry 4794 (class 2606 OID 25176)
-- Name: correlation_events correlation_events_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.correlation_events
    ADD CONSTRAINT correlation_events_pkey PRIMARY KEY (id);


--
-- TOC entry 4785 (class 2606 OID 25156)
-- Name: detection_rules detection_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_pkey PRIMARY KEY (id);


--
-- TOC entry 4787 (class 2606 OID 25158)
-- Name: detection_rules detection_rules_rule_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_rule_code_key UNIQUE (rule_code);


--
-- TOC entry 4851 (class 2606 OID 33896)
-- Name: incidents incidents_incident_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_incident_id_key UNIQUE (incident_id);


--
-- TOC entry 4853 (class 2606 OID 33894)
-- Name: incidents incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (id);


--
-- TOC entry 4776 (class 2606 OID 24592)
-- Name: invalid_logs invalid_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.invalid_logs
    ADD CONSTRAINT invalid_logs_pkey PRIMARY KEY (id);


--
-- TOC entry 4766 (class 2606 OID 16399)
-- Name: logs logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT logs_pkey PRIMARY KEY (id);


--
-- TOC entry 4837 (class 2606 OID 33101)
-- Name: notification_escalations notification_escalations_escalation_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_escalations
    ADD CONSTRAINT notification_escalations_escalation_id_key UNIQUE (escalation_id);


--
-- TOC entry 4839 (class 2606 OID 33099)
-- Name: notification_escalations notification_escalations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_escalations
    ADD CONSTRAINT notification_escalations_pkey PRIMARY KEY (id);


--
-- TOC entry 4845 (class 2606 OID 33138)
-- Name: notification_history notification_history_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_history
    ADD CONSTRAINT notification_history_pkey PRIMARY KEY (id);


--
-- TOC entry 4847 (class 2606 OID 33152)
-- Name: notification_metrics notification_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_metrics
    ADD CONSTRAINT notification_metrics_pkey PRIMARY KEY (id);


--
-- TOC entry 4843 (class 2606 OID 33127)
-- Name: notification_policies notification_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_policies
    ADD CONSTRAINT notification_policies_pkey PRIMARY KEY (id);


--
-- TOC entry 4841 (class 2606 OID 33116)
-- Name: notification_recipients notification_recipients_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notification_recipients
    ADD CONSTRAINT notification_recipients_pkey PRIMARY KEY (id);


--
-- TOC entry 4828 (class 2606 OID 33084)
-- Name: notifications notifications_notification_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_notification_fingerprint_key UNIQUE (notification_fingerprint);


--
-- TOC entry 4830 (class 2606 OID 33082)
-- Name: notifications notifications_notification_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_notification_id_key UNIQUE (notification_id);


--
-- TOC entry 4832 (class 2606 OID 33080)
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- TOC entry 4768 (class 2606 OID 16401)
-- Name: logs unique_windows_event; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.logs
    ADD CONSTRAINT unique_windows_event UNIQUE (source, host, event_type, record_number);


--
-- TOC entry 4783 (class 2606 OID 24616)
-- Name: unknown_logs unknown_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.unknown_logs
    ADD CONSTRAINT unknown_logs_pkey PRIMARY KEY (id);


--
-- TOC entry 4812 (class 1259 OID 32802)
-- Name: idx_alerts_correlation_matches; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_correlation_matches ON public.alerts USING gin (correlation_matches);


--
-- TOC entry 4813 (class 1259 OID 32798)
-- Name: idx_alerts_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_created_at ON public.alerts USING btree (created_at DESC);


--
-- TOC entry 4814 (class 1259 OID 32800)
-- Name: idx_alerts_fingerprint; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_fingerprint ON public.alerts USING btree (alert_fingerprint);


--
-- TOC entry 4815 (class 1259 OID 32796)
-- Name: idx_alerts_host; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_host ON public.alerts USING btree (host);


--
-- TOC entry 4816 (class 1259 OID 32799)
-- Name: idx_alerts_last_seen; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_last_seen ON public.alerts USING btree (last_seen DESC);


--
-- TOC entry 4817 (class 1259 OID 32793)
-- Name: idx_alerts_priority; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_priority ON public.alerts USING btree (priority);


--
-- TOC entry 4818 (class 1259 OID 32801)
-- Name: idx_alerts_rule_matches; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_rule_matches ON public.alerts USING gin (rule_matches);


--
-- TOC entry 4819 (class 1259 OID 32792)
-- Name: idx_alerts_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_severity ON public.alerts USING btree (severity);


--
-- TOC entry 4820 (class 1259 OID 32795)
-- Name: idx_alerts_source_ip; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_source_ip ON public.alerts USING btree (source_ip);


--
-- TOC entry 4821 (class 1259 OID 32794)
-- Name: idx_alerts_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_status ON public.alerts USING btree (status);


--
-- TOC entry 4822 (class 1259 OID 32797)
-- Name: idx_alerts_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_alerts_username ON public.alerts USING btree (username);


--
-- TOC entry 4795 (class 1259 OID 25188)
-- Name: idx_corr_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_created_at ON public.correlation_events USING btree (created_at);


--
-- TOC entry 4796 (class 1259 OID 25187)
-- Name: idx_corr_fingerprint; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_fingerprint ON public.correlation_events USING btree (event_fingerprint);


--
-- TOC entry 4797 (class 1259 OID 25185)
-- Name: idx_corr_first_seen; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_first_seen ON public.correlation_events USING btree (first_seen);


--
-- TOC entry 4798 (class 1259 OID 25183)
-- Name: idx_corr_host; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_host ON public.correlation_events USING btree (related_host);


--
-- TOC entry 4799 (class 1259 OID 25186)
-- Name: idx_corr_last_seen; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_last_seen ON public.correlation_events USING btree (last_seen);


--
-- TOC entry 4800 (class 1259 OID 25189)
-- Name: idx_corr_metadata; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_metadata ON public.correlation_events USING gin (correlation_metadata);


--
-- TOC entry 4801 (class 1259 OID 25180)
-- Name: idx_corr_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_severity ON public.correlation_events USING btree (severity);


--
-- TOC entry 4802 (class 1259 OID 25181)
-- Name: idx_corr_source_ip; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_source_ip ON public.correlation_events USING btree (related_source_ip);


--
-- TOC entry 4803 (class 1259 OID 25184)
-- Name: idx_corr_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_status ON public.correlation_events USING btree (correlation_status);


--
-- TOC entry 4804 (class 1259 OID 25179)
-- Name: idx_corr_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_type ON public.correlation_events USING btree (correlation_type);


--
-- TOC entry 4805 (class 1259 OID 25182)
-- Name: idx_corr_user; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_corr_user ON public.correlation_events USING btree (related_user);


--
-- TOC entry 4833 (class 1259 OID 33103)
-- Name: idx_escalation_alert; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_escalation_alert ON public.notification_escalations USING btree (alert_id);


--
-- TOC entry 4834 (class 1259 OID 33102)
-- Name: idx_escalation_notification; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_escalation_notification ON public.notification_escalations USING btree (notification_id);


--
-- TOC entry 4835 (class 1259 OID 33104)
-- Name: idx_escalation_time; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_escalation_time ON public.notification_escalations USING btree (escalated_at DESC);


--
-- TOC entry 4848 (class 1259 OID 33898)
-- Name: idx_incident_assigned; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_incident_assigned ON public.incidents USING btree (assigned_to);


--
-- TOC entry 4849 (class 1259 OID 33897)
-- Name: idx_incident_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_incident_status ON public.incidents USING btree (status);


--
-- TOC entry 4769 (class 1259 OID 24596)
-- Name: idx_invalid_logs_collector; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_invalid_logs_collector ON public.invalid_logs USING btree (collector_name);


--
-- TOC entry 4770 (class 1259 OID 24598)
-- Name: idx_invalid_logs_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_invalid_logs_hash ON public.invalid_logs USING btree (quarantine_hash);


--
-- TOC entry 4771 (class 1259 OID 24595)
-- Name: idx_invalid_logs_received_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_invalid_logs_received_at ON public.invalid_logs USING btree (received_at);


--
-- TOC entry 4772 (class 1259 OID 24593)
-- Name: idx_invalid_logs_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_invalid_logs_source ON public.invalid_logs USING btree (source);


--
-- TOC entry 4773 (class 1259 OID 24599)
-- Name: idx_invalid_logs_stage; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_invalid_logs_stage ON public.invalid_logs USING btree (validation_stage);


--
-- TOC entry 4774 (class 1259 OID 24594)
-- Name: idx_invalid_logs_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_invalid_logs_status ON public.invalid_logs USING btree (validation_status);


--
-- TOC entry 4823 (class 1259 OID 33085)
-- Name: idx_notifications_alert; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_notifications_alert ON public.notifications USING btree (alert_id);


--
-- TOC entry 4824 (class 1259 OID 33088)
-- Name: idx_notifications_created; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_notifications_created ON public.notifications USING btree (created_at DESC);


--
-- TOC entry 4825 (class 1259 OID 33087)
-- Name: idx_notifications_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_notifications_severity ON public.notifications USING btree (severity);


--
-- TOC entry 4826 (class 1259 OID 33086)
-- Name: idx_notifications_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_notifications_status ON public.notifications USING btree (status);


--
-- TOC entry 4788 (class 1259 OID 25159)
-- Name: idx_rules_enabled; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_rules_enabled ON public.detection_rules USING btree (is_enabled);


--
-- TOC entry 4789 (class 1259 OID 25161)
-- Name: idx_rules_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_rules_severity ON public.detection_rules USING btree (severity);


--
-- TOC entry 4790 (class 1259 OID 25160)
-- Name: idx_rules_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_rules_source ON public.detection_rules USING btree (source_type);


--
-- TOC entry 4777 (class 1259 OID 24622)
-- Name: idx_unknown_logs_confidence; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_unknown_logs_confidence ON public.unknown_logs USING btree (detection_confidence);


--
-- TOC entry 4778 (class 1259 OID 24617)
-- Name: idx_unknown_logs_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_unknown_logs_hash ON public.unknown_logs USING btree (unknown_hash);


--
-- TOC entry 4779 (class 1259 OID 24621)
-- Name: idx_unknown_logs_log_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_unknown_logs_log_type ON public.unknown_logs USING btree (log_type);


--
-- TOC entry 4780 (class 1259 OID 24618)
-- Name: idx_unknown_logs_received_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_unknown_logs_received_at ON public.unknown_logs USING btree (received_at);


--
-- TOC entry 4781 (class 1259 OID 24619)
-- Name: idx_unknown_logs_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_unknown_logs_source ON public.unknown_logs USING btree (source);


-- Completed on 2026-07-02 12:30:18

--
-- PostgreSQL database dump complete
--

\unrestrict FK4fwHr72XzHx3bRTrxdqJXip667VS9ZObLZakIDzsg4nbXavJqYbMki1ZrrvU1

